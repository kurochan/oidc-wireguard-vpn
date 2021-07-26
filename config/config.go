package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"gopkg.in/yaml.v2"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"kurochan.org/oidc-wireguard-vpn/netlink"
	"kurochan.org/oidc-wireguard-vpn/nftables"
	"kurochan.org/oidc-wireguard-vpn/oidc"
	"kurochan.org/oidc-wireguard-vpn/wireguard"
)

type Config struct {
	WireGuard    *wireguard.WireGuard
	Netlink      *netlink.Netlink
	Nftables     *nftables.Nftables
	OIDC         *oidc.OIDC
	PeerAndUsers map[string]string
}

type InputConfig struct {
	InterfaceName    string `yaml:"interface_name"`
	InterfaceIP      string `yaml:"interface_ip"`
	Port             int    `yaml:"port"`
	NATEnabled       bool   `yaml:"nat_enabled"`
	WGPrivateKey     string `yaml:"wg_private_key"`
	OIDCEndpoint     string `yaml:"oidc_endpoint"`
	OIDCClentID      string `yaml:"oidc_client_id"`
	OIDCClientSecret string `yaml:"oidc_client_secret"`
	Clients          []struct {
		UserID    string `yaml:"user_id"`
		PublicKey string `yaml:"public_key"`
		IP        string `yaml:"ip"`
	} `yaml:"clients"`
}

func createWireGuard(config *InputConfig) (*wireguard.WireGuard, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		zap.L().Error("failed to create WireGuard client", zap.Error(err))
		return nil, err
	}

	peers := make([]wireguard.PeerConfig, 0)
	for _, client := range config.Clients {
		_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/32", client.IP))
		if err != nil {
			zap.L().Error(fmt.Sprintf("failed to parse IP %s", client.IP), zap.Error(err))
			return nil, err
		}
		peer := wireguard.PeerConfig{
			PublicKey: client.PublicKey,
			AllowedIP: *cidr,
		}
		peers = append(peers, peer)
	}

	wg := wireguard.WireGuard{
		Client: wgClient,
		Config: wireguard.Config{
			DeviceName: config.InterfaceName,
			PrivateKey: config.WGPrivateKey,
			Port:       config.Port,
			Peers:      peers,
		},
	}

	return &wg, nil
}

func createNetlink(config *InputConfig) (*netlink.Netlink, error) {
	ip, cidr, err := net.ParseCIDR(config.InterfaceIP)
	if err != nil {
		zap.L().Error(fmt.Sprintf("failed to parse IP %s", config.InterfaceIP), zap.Error(err))
		return nil, err
	}
	cidr.IP = ip
	netlink := netlink.Netlink{
		Config: netlink.Config{
			DeviceName: config.InterfaceName,
			IPAddress:  cidr,
		},
	}
	return &netlink, nil
}

func createNftables(config *InputConfig) (*nftables.Nftables, error) {
	_, cidr, err := net.ParseCIDR(config.InterfaceIP)
	if err != nil {
		zap.L().Error(fmt.Sprintf("failed to parse IP %s", config.InterfaceIP), zap.Error(err))
		return nil, err
	}
	nftables := nftables.Nftables{
		Config: nftables.Config{
			TableName:        fmt.Sprintf("oidc-vpn-%s", config.InterfaceName),
			VPNInterfaceName: config.InterfaceName,
			VPNInterfaceIP:   *cidr,
			NATEnabled:       config.NATEnabled,
		},
	}
	return &nftables, nil
}

func createOIDC(config *InputConfig) (*oidc.OIDC, error) {
	oidc := oidc.OIDC{
		Config: oidc.Config{
			Endpoint:     config.OIDCEndpoint,
			ClientID:     config.OIDCClentID,
			ClientSecret: config.OIDCClientSecret,
		},
	}
	return &oidc, nil
}

func loadConfigFile(fileName string) (*InputConfig, error) {
	buf, err := ioutil.ReadFile(fileName)
	if err != nil {
		zap.L().Error(fmt.Sprintf("failed to load file %s", fileName), zap.Error(err))
		return nil, err
	}
	conf := InputConfig{}
	if err := yaml.Unmarshal(buf, &conf); err != nil {
		zap.L().Error(fmt.Sprintf("failed to load file %s", fileName), zap.Error(err))
		return nil, err
	}
	return &conf, nil
}

func overrideEnvConfig(config *InputConfig) error {
	if v := os.Getenv("WG_PRIVATE_KEY"); v != "" {
		config.WGPrivateKey = v
	}
	if config.WGPrivateKey == "" {
		return errors.New("environment variable WG_PRIVATE_KEY is required")
	}
	if v := os.Getenv("OIDC_CLIENT_ID"); v != "" {
		config.OIDCClentID = v
	}
	if config.OIDCClentID == "" {
		return errors.New("environment variable OIDC_CLIENT_ID is required")
	}
	if v := os.Getenv("OIDC_CLIENT_SECRET"); v != "" {
		config.OIDCClientSecret = v
	}
	if config.OIDCClientSecret == "" {
		return errors.New("environment variable OIDC_CLIENT_SECRET is required")
	}
	return nil
}

func createPeerAndUsers(config *InputConfig) map[string]string {
	peerAndUsers := make(map[string]string)
	for _, client := range config.Clients {
		peerAndUsers[client.PublicKey] = client.UserID
	}
	return peerAndUsers
}

func LoadConfig(fileName string) (*Config, error) {
	inputConfig, err := loadConfigFile(fileName)
	if err != nil {
		return nil, err
	}
	err = overrideEnvConfig(inputConfig)
	if err != nil {
		return nil, err
	}
	wg, err := createWireGuard(inputConfig)
	if err != nil {
		return nil, err
	}
	netlink, err := createNetlink(inputConfig)
	if err != nil {
		return nil, err
	}
	nftables, err := createNftables(inputConfig)
	if err != nil {
		return nil, err
	}
	oidc, err := createOIDC(inputConfig)
	if err != nil {
		return nil, err
	}
	peerAndUsers := createPeerAndUsers(inputConfig)
	config := &Config{
		WireGuard:    wg,
		Netlink:      netlink,
		Nftables:     nftables,
		OIDC:         oidc,
		PeerAndUsers: peerAndUsers,
	}
	return config, nil
}
