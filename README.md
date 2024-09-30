# About

Python API for SentinelOne

This code is released under the GNU LGPLv3 license <https://www.gnu.org/licenses/lgpl-3.0.en.html>.

# Usage

NOTE: **All API calls automatically handle pagination.**

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

data, errors = client.CountAgents(payload={'computerName__like': 'test'})

data, errors = c.ListUsers(payload={
        'skipCount': True,
        'query': 'Test'
    })
```
