```mermaid
stateDiagram
    [*] --> Unauthenticated : newUser()
    Unauthenticated --> Unauthenticated : invalidClearance/attributesRevoked
    Unauthenticated --> ABEAuthenticated : authorityDown/Delegate
    ABEAuthenticated --> FullyAuthenticated : authorityUp/Extract
    Unauthenticated --> FullyAuthenticated : authorityUp/KeyGen/Extract
    FullyAuthenticated --> [*]

```