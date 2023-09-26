# WfExS-backend security context

- [1. Pattern Property `WfExS-backend security context > Security context by name`](#pattern1)
  - [1.1. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 0`](#pattern1_pattern2_i0)
    - [1.1.1. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 0 > username`](#pattern1_pattern2_i0_username)
    - [1.1.2. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 0 > password`](#pattern1_pattern2_i0_password)
  - [1.2. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 1`](#pattern1_pattern2_i1)
    - [1.2.1. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 1 > access_key`](#pattern1_pattern2_i1_access_key)
    - [1.2.2. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 1 > secret_key`](#pattern1_pattern2_i1_secret_key)
  - [1.3. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 2`](#pattern1_pattern2_i2)
    - [1.3.1. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 2 > token`](#pattern1_pattern2_i2_token)
    - [1.3.2. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 2 > token_header`](#pattern1_pattern2_i2_token_header)
  - [1.4. Property `WfExS-backend security context > ^[^:;]+$ > method`](#pattern1_method)
  - [1.5. Property `WfExS-backend security context > ^[^:;]+$ > headers`](#pattern1_headers)
- [2. Pattern Property `WfExS-backend security context > Security context by prefix`](#pattern2)

**Title:** WfExS-backend security context

|                           |                                                         |
| ------------------------- | ------------------------------------------------------- |
| **Type**                  | `object`                                                |
| **Required**              | No                                                      |
| **Additional properties** | [[Not allowed]](# "Additional Properties not allowed.") |

**Description:** WfExS-backend security context file (EOSC-Life Demonstrator 7 JSON Schemas)

| Property                               | Pattern | Type   | Deprecated | Definition                     | Title/Description          |
| -------------------------------------- | ------- | ------ | ---------- | ------------------------------ | -------------------------- |
| - [^[^:;]+$](#pattern1 )               | Yes     | object | No         | In #/definitions/SecContext    | Security context by name   |
| - [^[a-z][a-z0-9+.-]*:.*$](#pattern2 ) | Yes     | object | No         | Same as [pattern1](#pattern1 ) | Security context by prefix |

## <a name="pattern1"></a>1. Pattern Property `WfExS-backend security context > Security context by name`
> All properties whose name matches the regular expression
```^[^:;]+$``` ([Test](https://regex101.com/?regex=%5E%5B%5E%3A%3B%5D%2B%24))
must respect the following conditions

**Title:** Security context by name

|                           |                                                                           |
| ------------------------- | ------------------------------------------------------------------------- |
| **Type**                  | `combining`                                                               |
| **Required**              | No                                                                        |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Defined in**            | #/definitions/SecContext                                                  |

| Property                        | Pattern | Type             | Deprecated | Definition | Title/Description                        |
| ------------------------------- | ------- | ---------------- | ---------- | ---------- | ---------------------------------------- |
| - [method](#pattern1_method )   | No      | enum (of string) | No         | -          | -                                        |
| - [headers](#pattern1_headers ) | No      | object           | No         | -          | Custom headers to be used on the request |

| One of(Option)                  |
| ------------------------------- |
| [item 0](#pattern1_pattern2_i0) |
| [item 1](#pattern1_pattern2_i1) |
| [item 2](#pattern1_pattern2_i2) |

### <a name="pattern1_pattern2_i0"></a>1.1. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 0`

|                           |                                                                           |
| ------------------------- | ------------------------------------------------------------------------- |
| **Type**                  | `object`                                                                  |
| **Required**              | No                                                                        |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |

| Property                                          | Pattern | Type   | Deprecated | Definition | Title/Description                            |
| ------------------------------------------------- | ------- | ------ | ---------- | ---------- | -------------------------------------------- |
| + [username](#pattern1_pattern2_i0_username )     | No      | string | No         | -          | The user name                                |
| + [password](#pattern1_pattern2_i0_password )     | No      | string | No         | -          | The user password associated to the username |
| - [](#pattern1_pattern2_i0_additionalProperties ) | No      | object | No         | -          | -                                            |

#### <a name="pattern1_pattern2_i0_username"></a>1.1.1. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 0 > username`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

**Description:** The user name

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |

#### <a name="pattern1_pattern2_i0_password"></a>1.1.2. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 0 > password`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

**Description:** The user password associated to the username

| Restrictions   |   |
| -------------- | - |
| **Min length** | 0 |

### <a name="pattern1_pattern2_i1"></a>1.2. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 1`

|                           |                                                                           |
| ------------------------- | ------------------------------------------------------------------------- |
| **Type**                  | `object`                                                                  |
| **Required**              | No                                                                        |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |

| Property                                          | Pattern | Type   | Deprecated | Definition | Title/Description |
| ------------------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [access_key](#pattern1_pattern2_i1_access_key ) | No      | string | No         | -          | -                 |
| + [secret_key](#pattern1_pattern2_i1_secret_key ) | No      | string | No         | -          | -                 |
| - [](#pattern1_pattern2_i1_additionalProperties ) | No      | object | No         | -          | -                 |

#### <a name="pattern1_pattern2_i1_access_key"></a>1.2.1. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 1 > access_key`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |

#### <a name="pattern1_pattern2_i1_secret_key"></a>1.2.2. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 1 > secret_key`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |

### <a name="pattern1_pattern2_i2"></a>1.3. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 2`

|                           |                                                                           |
| ------------------------- | ------------------------------------------------------------------------- |
| **Type**                  | `object`                                                                  |
| **Required**              | No                                                                        |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |

| Property                                              | Pattern | Type   | Deprecated | Definition | Title/Description                                                                                                                                                                                 |
| ----------------------------------------------------- | ------- | ------ | ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| + [token](#pattern1_pattern2_i2_token )               | No      | string | No         | -          | The authentication token                                                                                                                                                                          |
| - [token_header](#pattern1_pattern2_i2_token_header ) | No      | string | No         | -          | On HTTP, the authentication token is used to fill-in an 'Authentication: Bearer ' header. Sometimes authentication through tokens require using custom headers, like it happens with SevenBridges |
| - [](#pattern1_pattern2_i2_additionalProperties )     | No      | object | No         | -          | -                                                                                                                                                                                                 |

#### <a name="pattern1_pattern2_i2_token"></a>1.3.1. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 2 > token`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

**Description:** The authentication token

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |

#### <a name="pattern1_pattern2_i2_token_header"></a>1.3.2. Property `WfExS-backend security context > ^[^:;]+$ > oneOf > item 2 > token_header`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | No       |

**Description:** On HTTP, the authentication token is used to fill-in an 'Authentication: Bearer ' header. Sometimes authentication through tokens require using custom headers, like it happens with SevenBridges

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |

### <a name="pattern1_method"></a>1.4. Property `WfExS-backend security context > ^[^:;]+$ > method`

|              |                    |
| ------------ | ------------------ |
| **Type**     | `enum (of string)` |
| **Required** | No                 |
| **Default**  | `"GET"`            |

Must be one of:
* "GET"
* "POST"

### <a name="pattern1_headers"></a>1.5. Property `WfExS-backend security context > ^[^:;]+$ > headers`

|                           |                                                                           |
| ------------------------- | ------------------------------------------------------------------------- |
| **Type**                  | `object`                                                                  |
| **Required**              | No                                                                        |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |

**Description:** Custom headers to be used on the request

## <a name="pattern2"></a>2. Pattern Property `WfExS-backend security context > Security context by prefix`
> All properties whose name matches the regular expression
```^[a-z][a-z0-9+.-]*:.*$``` ([Test](https://regex101.com/?regex=%5E%5Ba-z%5D%5Ba-z0-9%2B.-%5D%2A%3A.%2A%24))
must respect the following conditions

**Title:** Security context by prefix

|                           |                                                                           |
| ------------------------- | ------------------------------------------------------------------------- |
| **Type**                  | `combining`                                                               |
| **Required**              | No                                                                        |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Same definition as**    | [pattern1](#pattern1)                                                     |

----------------------------------------------------------------------------------------------------------------------------
Generated using [json-schema-for-humans](https://github.com/coveooss/json-schema-for-humans) on 2023-09-26 at 08:59:04 +0000
