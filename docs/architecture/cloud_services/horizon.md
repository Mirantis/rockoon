# Horizon Configuration

This article describes horizon configuration.

## Custom Themes

To apply custom horizon theme on your environment use the following
snippet for `OpenStackDeployment` custom resource:


```yaml
spec:
  features:
    horizon:
      themes:
      - description: my custom theme
        name: AwesomTheme
        url: https://url/to/theme.tar.gz
        sha256summ: "sha256 of theme archive"
        enabled: true
```

By default `Mirantis` theme is enabled, to disabled it use

```yaml
spec:
  features:
    horizon:
      themes:
      - name: mirantis
        enabled: false
```
