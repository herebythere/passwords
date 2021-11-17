# Passwords

Utility functions to hash and salt passwords with argon2 encryption.

## v0.1

### Types

```
HashParams {
	hash_function string
	memory       uint32
	time         uint32
	threads      uint8
	salt_length  uint32
	salt_length  uint32
}
```

```
HashResults {
	salt   string
	hash   string
	params HashParams
}
```

### Properties

```
DefaultHashParams = HashParams{
    hash_function:  "argon2",
    memory:         32 * 1024,
    time:           3,
    threads:        4,
    salt_length:    32,
    key_length:     32,
}
```

### Functions


```
HashPassword(string, HashParams)->HashResults`
```


```
VerifyPassword(string, HashResults)->boolean`
```
