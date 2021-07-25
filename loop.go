package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"kurochan.org/oidc-wireguard-vpn/config"
)

const (
	LoopInterval          = 1
	AuthenticationTimeout = 180 * time.Second
	// https://github.com/E3V3A/WireGuard/blob/master/src/messages.h
	RekeyAfterTime   = 120
	WGSessionTimeout = (RekeyAfterTime + 30) * time.Second
)

type Loop struct {
	Config   *config.Config
	Context  context.Context
	Done     chan struct{}
	sessions *Sessions
}

type Session struct {
	PublicKey    string
	StartAt      time.Time
	WgExpireAt   time.Time
	OidcExpireAt time.Time
}

type Sessions struct {
	mutex    sync.Mutex
	Sessions map[string]*Session
}

func (s *Sessions) Lock() {
	s.mutex.Lock()
}

func (s *Sessions) Unlock() {
	s.mutex.Unlock()
}

func (l *Loop) checkSessionExpired(session *Session, now time.Time) bool {
	if session != nil {
		return now.After(session.WgExpireAt) || now.After(session.OidcExpireAt)
	}
	return true
}

func (l *Loop) checkAuthenticationRequired(peer string, now time.Time) bool {
	if session := l.sessions.Sessions[peer]; session != nil {
		return now.After(session.WgExpireAt) || now.After(session.OidcExpireAt)
	}
	return true
}

func (l *Loop) mergeNewSession(peer string, expiresIn int, now time.Time) {
	if session := l.sessions.Sessions[peer]; session != nil {
		zap.L().Debug(fmt.Sprintf("peer %s updated", peer))
		wgExpireAt := now.Add(WGSessionTimeout)
		session.WgExpireAt = wgExpireAt
	} else {
		zap.L().Debug(fmt.Sprintf("new peer %s added to sessions", peer))
		wgExpireAt := now.Add(WGSessionTimeout + AuthenticationTimeout)
		oidcExpireAt := now.Add(time.Duration(expiresIn) * time.Second)
		session := &Session{
			PublicKey:    peer,
			StartAt:      now,
			WgExpireAt:   wgExpireAt,
			OidcExpireAt: oidcExpireAt,
		}
		l.sessions.Sessions[peer] = session
	}
}

func (l *Loop) checkNewPeers(now time.Time) ([]string, error) {
	peers, err := l.Config.WireGuard.ListPeers()
	if err != nil {
		zap.L().Error("cannot get WireGuard peers", zap.Error(err))
		return nil, err
	}

	newSessions := make([]string, 0)
	for _, peer := range peers {
		if peer.LastHandshakeTime.After(now) {
			zap.L().Info(fmt.Sprintf("new session detected from: %s", peer.PublicKey))
			newSessions = append(newSessions, peer.PublicKey)
		}
	}
	return newSessions, nil
}

func (l *Loop) handleNewSessions(peers []string, now time.Time) {
	waitList := make([]chan struct{}, 0)

	for _, peer := range peers {
		done := make(chan struct{})
		waitList = append(waitList, done)
		go l.handleNewSession(peer, now, done)
	}

	timeOut := time.After(time.Second * 180)
	for _, done := range waitList {
		select {
		case <-timeOut:
			zap.L().Error("handle new sessions timed out!! (maybe goroutine leak)")
			return
		case <-done:
		}
	}
	zap.L().Debug("handle new sessions completed")
}

func (l *Loop) handleNewSession(peer string, now time.Time, done chan struct{}) {
	l.sessions.Lock()
	authnRequired := l.checkAuthenticationRequired(peer, now)
	l.sessions.Unlock()

	if !authnRequired {
		zap.L().Debug(fmt.Sprintf("session is active, skip authentication: %s", peer))
		l.sessions.Lock()
		l.mergeNewSession(peer, 0, now)
		ipNet, err := l.Config.WireGuard.EnablePeer(peer)
		if err != nil {
			close(done)
			return
		}
		if err := l.Config.Nftables.AddAllowedIP(ipNet.IP.To4()); err != nil {
			close(done)
			return
		}
		l.sessions.Unlock()
		close(done)
		return
	}

	zap.L().Info(fmt.Sprintf("oidc ciba request initiated: %s", peer))
	uid := l.Config.PeerAndUsers[peer]
	code := peer
	expiresIn, err := l.Config.OIDC.Authenticate(uid, code)
	if err == nil {
		l.sessions.Lock()
		l.mergeNewSession(peer, expiresIn, now)
		ipNet, err := l.Config.WireGuard.EnablePeer(peer)
		if err != nil {
			close(done)
			return
		}
		if err := l.Config.Nftables.AddAllowedIP(ipNet.IP.To4()); err != nil {
			close(done)
			return
		}
		l.sessions.Unlock()
	}
	close(done)
}

func (l *Loop) checkExpiredPeers(now time.Time) []string {
	expiredPeers := make([]string, 0)
	l.sessions.Lock()
	for _, session := range l.sessions.Sessions {
		if l.checkSessionExpired(session, now) {
			expiredPeers = append(expiredPeers, session.PublicKey)
		}
	}
	l.sessions.Unlock()

	return expiredPeers
}

func (l *Loop) handleExpiredSessions(peers []string, now time.Time) {
	for _, peer := range peers {
		_ = l.handleExpiredSession(peer, now)
	}
	zap.L().Debug("handle expired sessions completed")
}

func (l *Loop) handleExpiredSession(peer string, now time.Time) error {
	zap.L().Info(fmt.Sprintf("session expired: %s", peer))
	ipNet, err := l.Config.WireGuard.DisablePeer(peer)
	if err != nil {
		return err
	}
	if err = l.Config.Nftables.DeleteAllowedIP(ipNet.IP.To4()); err != nil {
		return err
	}
	delete(l.sessions.Sessions, peer)
	return nil
}

func (l *Loop) loop() {
	lastSessionCheckTime := time.Now()
	l.sessions = &Sessions{
		Sessions: make(map[string]*Session),
	}

	for {
		select {
		case <-l.Context.Done():
			close(l.Done)
			return
		case <-time.After(LoopInterval * time.Second):
			zap.L().Debug(fmt.Sprintf("loop: last session check time: %s", lastSessionCheckTime))
		}
		now := time.Now()

		newPeers, _ := l.checkNewPeers(lastSessionCheckTime)
		if len(newPeers) > 0 {
			go l.handleNewSessions(newPeers, now)
		}

		expiredPeers := l.checkExpiredPeers(now)
		if len(expiredPeers) > 0 {
			go l.handleExpiredSessions(expiredPeers, now)
		}
		lastSessionCheckTime = now
	}
}
