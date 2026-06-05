package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"

	"sing-box-next-panel/services/controlplane"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	flag.Parse()

	cp := controlplane.New(nil)
	adminUser := getenv("MI_PANEL_ADMIN_USER", "admin")
	adminTenant := getenv("MI_PANEL_ADMIN_TENANT", "tenant-a")
	if password := os.Getenv("MI_PANEL_ADMIN_PASSWORD"); password != "" {
		if err := cp.ConfigurePasswordLogin(controlplane.PasswordLoginConfig{
			Username: adminUser,
			Password: password,
			UserID:   adminUser,
			TenantID: adminTenant,
			Role:     controlplane.RoleAdmin,
		}); err != nil {
			log.Fatal("invalid password login configuration")
		}
	}
	if token := os.Getenv("MI_PANEL_DEFAULT_SUBSCRIPTION_TOKEN"); token != "" {
		if _, err := cp.ConfigureDefaultSubscription(controlplane.DefaultSubscriptionConfig{
			Token:          token,
			UserID:         getenv("MI_PANEL_DEFAULT_SUBSCRIPTION_USER", adminUser),
			TenantID:       adminTenant,
			ClientType:     getenv("MI_PANEL_DEFAULT_SUBSCRIPTION_CLIENT", "sing-box"),
			DeviceID:       getenv("MI_PANEL_DEFAULT_SUBSCRIPTION_DEVICE", "default"),
			Region:         getenv("MI_PANEL_DEFAULT_SUBSCRIPTION_REGION", "auto"),
			Protocol:       getenv("MI_PANEL_DEFAULT_SUBSCRIPTION_PROTOCOL", "vless"),
			OutboundPolicy: getenv("MI_PANEL_DEFAULT_SUBSCRIPTION_OUTBOUND", "proxy-default"),
		}); err != nil {
			log.Fatal("invalid default subscription configuration")
		}
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Printf("requested address %s unavailable: %v; switching to a dynamic local port", *addr, err)
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("control plane listening on http://%s", listener.Addr().String())
	if err := http.Serve(listener, controlplane.NewHTTPHandler(cp)); err != nil {
		log.Fatal(err)
	}
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
