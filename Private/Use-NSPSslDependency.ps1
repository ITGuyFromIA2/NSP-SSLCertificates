function Use-NSPSslDependency {
    # Loads NSP.Bootstrap (elevation) for the commands that need it. The rest of the module doesn't,
    # so it still imports on a bare host.
    Import-NSPToolkitModule -Name NSP.Bootstrap -MinimumVersion 0.1.3
}
