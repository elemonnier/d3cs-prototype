```mermaid
stateDiagram
    [*] --> Ciphertext : selectCT()
    Ciphertext --> Ciphertext : revokedAttribute()/insufficientAttributes()
    Ciphertext --> Decrypted : verifyOK()
    Decrypted --> [*]
```