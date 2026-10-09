(import 'config.libsonnet') +
(import 'alerts.libsonnet') +
{
  grafanaDashboards+:: {
    'iptables.json': (import '../dashboards/iptables.json'),
  },
}
