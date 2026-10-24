package tunnel

import (
	"bytes"
	"html/template"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/mmatczuk/go-http-tunnel/id"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

type dashboardTunnel struct {
	Client   id.ID
	Name     string
	Protocol string
	Address  string
	Port     string
}

func (r *registry) dashboardSnapshot() []dashboardTunnel {
	r.mu.RLock()
	var rows []dashboardTunnel
	for identifier, item := range r.items {
		if item == voidRegistryItem {
			continue
		}
		for _, metadata := range item.dashboard {
			row := metadata
			row.Client = identifier
			rows = append(rows, row)
		}
	}
	r.mu.RUnlock()
	for i := range rows {
		switch rows[i].Protocol {
		case proto.TCP, proto.TCP4, proto.TCP6:
			_, rows[i].Port, _ = net.SplitHostPort(rows[i].Address)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Client != b.Client {
			return a.Client.String() < b.Client.String()
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Address < b.Address
	})
	return rows
}

// DashboardHandler returns a read-only view of registered tunnels for a separate
// HTTP listener. The handler has no authentication; bind it to a trusted interface.
func (s *Server) DashboardHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data := struct {
			Rows []dashboardTunnel
			Time string
		}{s.registry.dashboardSnapshot(), time.Now().UTC().Format("2006-01-02 15:04:05 UTC")}
		var body bytes.Buffer
		if err := dashboardTemplate.Execute(&body, data); err != nil {
			http.Error(w, "Dashboard unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodGet {
			w.Write(body.Bytes())
		}
	})
}

var dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="10"><title>隧道管理</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:#17263c;font:16px/1.6 system-ui,sans-serif}main{max-width:1160px;margin:48px auto;padding:0 24px}header{display:flex;align-items:center;justify-content:space-between;gap:20px}h1{font-size:28px;margin:0}p{color:#54647a}a{color:#1759b4}table{width:100%;border-collapse:collapse;background:white;border:1px solid #dce3ec;border-radius:12px}th,td{text-align:left;padding:16px;vertical-align:top;border-bottom:1px solid #e6ebf1;overflow-wrap:anywhere}th{font-size:14px;color:#54647a}td:first-child{font-weight:600}small{display:block;font-weight:400;color:#54647a}.empty{padding:48px 24px;background:white;border:1px solid #dce3ec;border-radius:12px;text-align:center}.port{font-weight:600}.note{font-size:14px}
@media(max-width:700px){main{margin:24px auto;padding:0 16px}header{align-items:flex-start}h1{font-size:24px}table,tbody,tr,td{display:block}table{border:0;background:transparent}thead{display:none}tr{background:white;border:1px solid #dce3ec;border-radius:12px;margin-bottom:16px;padding:8px 16px}td{padding:10px 0;border-bottom:1px solid #eef1f5}td:before{content:attr(data-label);display:block;font-size:13px;color:#54647a;font-weight:400}td:last-child{border:0}}
</style></head><body><main><header><h1>已注册隧道</h1><a href="/">立即刷新</a></header><p>共 {{len .Rows}} 条隧道 · 快照时间 {{.Time}}</p>
{{if .Rows}}<table><thead><tr><th>隧道 / 客户端</th><th>协议</th><th>监听地址 / 主机</th><th>端口</th></tr></thead><tbody>{{range .Rows}}<tr><td data-label="隧道 / 客户端">{{.Name}}<small>{{.Client}}</small></td><td data-label="协议">{{.Protocol}}</td><td data-label="监听地址 / 主机">{{.Address}}</td><td data-label="端口" class="port">{{if eq .Protocol "http"}}共享 HTTP/HTTPS 入口，无独立端口{{else if .Port}}{{.Port}}{{else}}不适用（UNIX 套接字）{{end}}</td></tr>{{end}}</tbody></table>{{else}}<div class="empty">暂无已注册隧道<br><small>客户端连接并成功注册隧道后，将显示在这里。</small></div>{{end}}
<p class="note">每 10 秒自动刷新。此页展示注册信息，不代表后端健康状态。监听地址可能是通配地址，并非可直接访问的公网链接。</p></main></body></html>`))
