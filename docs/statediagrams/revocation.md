```mermaid
stateDiagram
[*] --> Unrevoked : selectAttribute()
[*] --> Revoked : selectAttribute()
Unrevoked --> Revoked : revokeAttribute()
Revoked --> Unrevoked : unrevokeAttribute()
Revoked --> [*]
Unrevoked --> [*]

```