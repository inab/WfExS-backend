# WfExS-backend security context

- [1. [Optional]Pattern Property `WfExS-backend security context > Security context`](#pattern1)
  - [1.1. Property `WfExS-backend security context > Security context > oneOf > item 0`](#pattern1_oneOf_i0)
    - [1.1.1. Property `WfExS-backend security context > Security context > oneOf > item 0 > username`](#pattern1_oneOf_i0_username)
    - [1.1.2. Property `WfExS-backend security context > Security context > oneOf > item 0 > password`](#pattern1_oneOf_i0_password)
  - [1.2. Property `WfExS-backend security context > Security context > oneOf > item 1`](#pattern1_oneOf_i1)
    - [1.2.1. Property `WfExS-backend security context > Security context > oneOf > item 1 > access_key`](#pattern1_oneOf_i1_access_key)
    - [1.2.2. Property `WfExS-backend security context > Security context > oneOf > item 1 > secret_key`](#pattern1_oneOf_i1_secret_key)
  - [1.3. Property `WfExS-backend security context > Security context > oneOf > item 2`](#pattern1_oneOf_i2)
    - [1.3.1. Property `WfExS-backend security context > Security context > oneOf > item 2 > token`](#pattern1_oneOf_i2_token)
    - [1.3.2. Property `WfExS-backend security context > Security context > oneOf > item 2 > token_header`](#pattern1_oneOf_i2_token_header)
  - [1.4. [Optional] Property `WfExS-backend security context > Security context > method`](#pattern1_method)
  - [1.5. [Optional] Property `WfExS-backend security context > Security context > headers`](#pattern1_headers)

**Title:** WfExS-backend security context

| Type                      | `object`                                                |
| ------------------------- | ------------------------------------------------------- |
| **Additional properties** | [[Not allowed]](# "Additional Properties not allowed.") |
|                           |                                                         |

**Description:** WfExS-backend security context file (EOSC-Life Demonstrator 7 JSON Schemas)

| Property             | Pattern | Type        | Deprecated | Definition | Title/Description |
| -------------------- | ------- | ----------- | ---------- | ---------- | ----------------- |
| - [^.+$](#pattern1 ) | Yes     | Combination | No         | -          | Security context  |
|                      |         |             |            |            |                   |

## <a name="pattern1"></a>1. [Optional]Pattern Property `WfExS-backend security context > Security context`
> All property whose name matches the regular expression 
```^.+$``` ([Test](https://regex101.com/?regex=%5E.%2B%24))
must respect the following conditions

**Title:** Security context

| Type                      | `combining`                                                               |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Property                        | Pattern | Type             | Deprecated | Definition | Title/Description                        |
| ------------------------------- | ------- | ---------------- | ---------- | ---------- | ---------------------------------------- |
| - [method](#pattern1_method )   | No      | enum (of string) | No         | -          | -                                        |
| - [headers](#pattern1_headers ) | No      | object           | No         | -          | Custom headers to be used on the request |
|                                 |         |                  |            |            |                                          |

| One of(Option)               |
| ---------------------------- |
| [item 0](#pattern1_oneOf_i0) |
| [item 1](#pattern1_oneOf_i1) |
| [item 2](#pattern1_oneOf_i2) |
|                              |

### <a name="pattern1_oneOf_i0"></a>1.1. Property `WfExS-backend security context > Security context > oneOf > item 0`

| Type                      | `object`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Property                                   | Pattern | Type   | Deprecated | Definition | Title/Description                            |
| ------------------------------------------ | ------- | ------ | ---------- | ---------- | -------------------------------------------- |
| + [username](#pattern1_oneOf_i0_username ) | No      | string | No         | -          | The user name                                |
| + [password](#pattern1_oneOf_i0_password ) | No      | string | No         | -          | The user password associated to the username |
|                                            |         |        |            |            |                                              |

#### <a name="pattern1_oneOf_i0_username"></a>1.1.1. Property `WfExS-backend security context > Security context > oneOf > item 0 > username`

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** The user name

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

#### <a name="pattern1_oneOf_i0_password"></a>1.1.2. Property `WfExS-backend security context > Security context > oneOf > item 0 > password`

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** The user password associated to the username

| Restrictions   |   |
| -------------- | - |
| **Min length** | 0 |
|                |   |

### <a name="pattern1_oneOf_i1"></a>1.2. Property `WfExS-backend security context > Security context > oneOf > item 1`

| Type                      | `object`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Property                                       | Pattern | Type   | Deprecated | Definition | Title/Description |
| ---------------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [access_key](#pattern1_oneOf_i1_access_key ) | No      | string | No         | -          | -                 |
| + [secret_key](#pattern1_oneOf_i1_secret_key ) | No      | string | No         | -          | -                 |
|                                                |         |        |            |            |                   |

#### <a name="pattern1_oneOf_i1_access_key"></a>1.2.1. Property `WfExS-backend security context > Security context > oneOf > item 1 > access_key`

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

#### <a name="pattern1_oneOf_i1_secret_key"></a>1.2.2. Property `WfExS-backend security context > Security context > oneOf > item 1 > secret_key`

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

### <a name="pattern1_oneOf_i2"></a>1.3. Property `WfExS-backend security context > Security context > oneOf > item 2`

| Type                      | `object`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Property                                           | Pattern | Type   | Deprecated | Definition | Title/Description                                                                    |
| -------------------------------------------------- | ------- | ------ | ---------- | ---------- | ------------------------------------------------------------------------------------ |
| + [token](#pattern1_oneOf_i2_token )               | No      | string | No         | -          | The authentication token                                                             |
| - [token_header](#pattern1_oneOf_i2_token_header ) | No      | string | No         | -          | On HTTP, the authentication token is used to fill-in an 'Authentication: Bearer  ... |
|                                                    |         |        |            |            |                                                                                      |

#### <a name="pattern1_oneOf_i2_token"></a>1.3.1. Property `WfExS-backend security context > Security context > oneOf > item 2 > token`

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** The authentication token

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

#### <a name="pattern1_oneOf_i2_token_header"></a>1.3.2. Property `WfExS-backend security context > Security context > oneOf > item 2 > token_header`

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** On HTTP, the authentication token is used to fill-in an 'Authentication: Bearer ' header. Sometimes authentication through tokens require using custom headers, like it happens with SevenBridges

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

### <a name="pattern1_method"></a>1.4. [Optional] Property `WfExS-backend security context > Security context > method`

| Type                      | `enum (of string)`                                                        |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"GET"`                                                                   |
|                           |                                                                           |

Must be one of:
* "GET"
* "POST"

### <a name="pattern1_headers"></a>1.5. [Optional] Property `WfExS-backend security context > Security context > headers`

| Type                      | `object`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** Custom headers to be used on the request

----------------------------------------------------------------------------------------------------------------------------
Generated using [json-schema-for-humans](https://github.com/coveooss/json-schema-for-humans) on 2022-04-06 at 03:20:33 +0200