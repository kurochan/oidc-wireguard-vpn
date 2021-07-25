package wireguard

import (
	"net"
	"time"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	PublicKey         string
	LastHandshakeTime time.Time
}

type Config struct {
	DeviceName string
	PrivateKey string
	Port       int
	Peers      []PeerConfig
}

type PeerConfig struct {
	PublicKey string
	AllowedIP net.IPNet
}

type WireGuard struct {
	Config Config
	Client *wgctrl.Client
}

func (w *WireGuard) Init() error {
	privateKey, err := wgtypes.ParseKey(w.Config.PrivateKey)
	if err != nil {
		zap.L().Error("invalid private key", zap.Error(err))
		return err
	}

	peers := make([]wgtypes.PeerConfig, 0)
	for _, peerConf := range w.Config.Peers {
		publicKey, err := wgtypes.ParseKey(peerConf.PublicKey)
		if err != nil {
			zap.L().Error("invalid public key", zap.Error(err))
			return err
		}
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey: publicKey,
			// deny all traffic
			AllowedIPs:        []net.IPNet{},
			ReplaceAllowedIPs: true,
		})
	}

	wgConfig := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &w.Config.Port,
		ReplacePeers: true,
		Peers:        peers,
	}

	if err := w.Client.ConfigureDevice(w.Config.DeviceName, wgConfig); err != nil {
		zap.L().Error("failed to initialize wireguard device", zap.Error(err))
		return err
	}
	return nil
}

func (w *WireGuard) ListPeers() ([]*Peer, error) {
	device, err := w.Client.Device(w.Config.DeviceName)
	if err != nil {
		zap.L().Error("cannot create WireGuard client")
		return nil, err
	}

	peers := make([]*Peer, 0)
	for _, peer := range device.Peers {
		peers = append(peers, &Peer{
			PublicKey:         peer.PublicKey.String(),
			LastHandshakeTime: peer.LastHandshakeTime,
		})
	}
	return peers, nil
}

func (w *WireGuard) EnablePeer(publicKey string) (*net.IPNet, error) {
	var peer wgtypes.PeerConfig
	var allowedIP net.IPNet
	for _, peerConf := range w.Config.Peers {
		if peerConf.PublicKey == publicKey {
			publicKey, err := wgtypes.ParseKey(peerConf.PublicKey)
			if err != nil {
				zap.L().Error("invalid public key", zap.Error(err))
				return nil, err
			}
			allowedIP = peerConf.AllowedIP
			peer = wgtypes.PeerConfig{
				PublicKey:         publicKey,
				AllowedIPs:        []net.IPNet{peerConf.AllowedIP},
				ReplaceAllowedIPs: true,
			}
			break
		}
	}
	peers := []wgtypes.PeerConfig{peer}

	wgConfig := wgtypes.Config{
		ReplacePeers: false,
		Peers:        peers,
	}

	if err := w.Client.ConfigureDevice(w.Config.DeviceName, wgConfig); err != nil {
		zap.L().Error("failed to update wireguard device", zap.Error(err))
		return nil, err
	}
	return &allowedIP, nil
}

func (w *WireGuard) DisablePeer(publicKey string) (*net.IPNet, error) {
	var peer wgtypes.PeerConfig
	var allowedIP net.IPNet
	for _, peerConf := range w.Config.Peers {
		if peerConf.PublicKey == publicKey {
			publicKey, err := wgtypes.ParseKey(peerConf.PublicKey)
			if err != nil {
				zap.L().Error("invalid public key", zap.Error(err))
				return nil, err
			}
			allowedIP = peerConf.AllowedIP
			peer = wgtypes.PeerConfig{
				PublicKey: publicKey,
				// deny all traffic
				AllowedIPs:        []net.IPNet{},
				ReplaceAllowedIPs: true,
			}
			break
		}
	}
	peers := []wgtypes.PeerConfig{peer}

	wgConfig := wgtypes.Config{
		ReplacePeers: false,
		Peers:        peers,
	}

	if err := w.Client.ConfigureDevice(w.Config.DeviceName, wgConfig); err != nil {
		zap.L().Error("failed to update wireguard device", zap.Error(err))
		return nil, err
	}
	return &allowedIP, nil
}
