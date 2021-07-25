package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"kurochan.org/oidc-wireguard-vpn/config"
)

func setup(config *config.Config, done chan struct{}, success *bool) {
	*success = false

	if err := config.Netlink.CreateInterface(); err != nil {
		close(done)
		return
	}
	if err := config.Nftables.InitNftable(); err != nil {
		close(done)
		return
	}
	if err := config.WireGuard.Init(); err != nil {
		close(done)
		return
	}
	*success = true
	close(done)
}

func shutdown(config *config.Config, done chan struct{}) {
	if err := config.Netlink.DeleteInterface(); err != nil {
		close(done)
		return
	}
	if err := config.Nftables.DeleteNfTable(); err != nil {
		close(done)
		return
	}
	close(done)
}

func replaceLogger() (*zap.Logger, func(), error) {
	logger, err := zap.NewProduction()
	if strings.ToLower(os.Getenv("LOG_LEVEL")) == "development" {
		logger, err = zap.NewDevelopment()
	}
	undoReplaceLogger := zap.ReplaceGlobals(logger)
	return logger, undoReplaceLogger, err
}

func main() {
	logger, undoReplaceLogger, _ := replaceLogger()
	defer func() { _ = logger.Sync() }()
	defer undoReplaceLogger()

	if len(os.Args) != 2 {
		zap.L().Error("invalid number of command arguments")
		return
	}
	fileName := os.Args[1]

	zap.L().Info("initializing")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	config, err := config.LoadConfig(fileName)
	if err != nil {
		zap.L().Error("failed to load initialize config", zap.Error(err))
		return
	}
	rootCtx := context.Background()

	var success bool
	initDone := make(chan struct{})
	go setup(config, initDone, &success)
	select {
	case <-time.After(time.Second * 3):
		zap.L().Error("init process Failed")
	case <-initDone:
	}

	if success {
		loopDone := make(chan struct{})
		loopCtx, loopCancel := context.WithCancel(rootCtx)
		defer loopCancel()
		loop := &Loop{
			Config:  config,
			Context: loopCtx,
			Done:    loopDone,
		}
		go loop.loop()
		zap.L().Info("oidc-wireguard-vpn started")
		sig := <-sigs
		zap.L().Info("got signal: " + sig.String())
		loopCancel()
		select {
		case <-time.After(time.Second * 3):
			zap.L().Warn("stop loop failed")
		case <-loopDone:
			zap.L().Info("loop end")
		}
	} else {
		zap.L().Error("failed to startup")
	}

	zap.L().Info("shutdown process")
	shutdownDone := make(chan struct{})
	go shutdown(config, shutdownDone)
	select {
	case <-time.After(time.Second * 3):
		zap.L().Warn("shutdown process Failed")
		success = false
	case <-shutdownDone:
	}

	zap.L().Info("shutdown complete")
	if success {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
