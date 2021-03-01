# Usage

```python
import sentineloneapi

client = sentineloneapi.Client(
                    username='username@domain.tld',
                    password='PASSWORD_HERE',
                    url='example.sentinelone.net'
                )

# One or the other.
# Username/password and apitoken are mutually exclusive.

client = sentineloneapi.Client(
                    apitoken='TOKEN_HERE',
                    url='example.sentinelone.net'
                )

client.authenticate()
```