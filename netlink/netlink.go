package netlink

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

type Config struct {
	DeviceName string
	IPAddress  *net.IPNet
}

type Netlink struct {
	Config        Config
	deviceCreated bool
}

func (n *Netlink) CreateInterface() error {
	n.deviceCreated = false
	if wg, _ := netlink.LinkByName(n.Config.DeviceName); wg != nil {
		zap.L().Error(fmt.Sprintf("device already exists %s", wg.Attrs().Name))
		return fmt.Errorf("device already exists %s", wg.Attrs().Name)
	}
	la := netlink.NewLinkAttrs()
	la.Name = n.Config.DeviceName
	wg := &netlink.Wireguard{LinkAttrs: la}

	if err := netlink.LinkAdd(wg); err != nil {
		zap.L().Error(fmt.Sprintf("could not add %s", la.Name), zap.Error(err))
		return err
	}
	n.deviceCreated = true

	addr := &netlink.Addr{IPNet: n.Config.IPAddress}
	if err := netlink.AddrAdd(wg, addr); err != nil {
		zap.L().Error(fmt.Sprintf("could not add addr %s to %s", addr, la.Name), zap.Error(err))
		return err
	}

	if err := netlink.LinkSetUp(wg); err != nil {
		zap.L().Error(fmt.Sprintf("could not link up %s", la.Name), zap.Error(err))
		return err
	}
	return nil
}

func (n *Netlink) DeleteInterface() error {
	if !n.deviceCreated {
		zap.L().Warn("device not created. skip delete interface")
		return nil
	}
	wg, err := netlink.LinkByName(n.Config.DeviceName)
	if err != nil {
		zap.L().Warn(fmt.Sprintf("could not get interface %s", n.Config.DeviceName), zap.Error(err))
		return err
	}
	if err := netlink.LinkDel(wg); err != nil {
		zap.L().Error(fmt.Sprintf("could not delete interface %s", wg.Attrs().Name), zap.Error(err))
		return err
	}
	return nil
}
