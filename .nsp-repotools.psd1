@{
    # Settings for NSP.RepoTools. Tracked: name what is accepted, never a client.
    ClientSweep = @{
        # The smoke test asserts the PEM header of the keys it generates ('-----BEGIN PRIVATE KEY-----'
        # as text, no key). Excluded by path rather than allowing that text, so a real key anywhere
        # else in this repository is still caught. Test-Repo's private-term check still scans it.
        ExcludePath = @('Tests/Smoke.ps1')
    }
}
