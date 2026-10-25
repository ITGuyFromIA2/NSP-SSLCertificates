@{
    # Settings for NSP.RepoTools. Tracked: name what is accepted, never a client.
    ClientSweep = @{
        # The smoke test asserts the PEM header line of the keys it generates (text, no key), and an
        # earlier revision of this file quoted it. Excluded by path rather than allowing that text, so
        # a real key anywhere else in the repository is still caught. Test-Repo's private-term check
        # still scans the smoke test.
        ExcludePath = @('Tests/Smoke.ps1', '.nsp-repotools.psd1')
    }
}
