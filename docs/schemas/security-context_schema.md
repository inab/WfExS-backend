# WfExS-backend security context

- [1. [Optional]Pattern Property `WfExS-backend security context > Security context`](#pattern1)
  - [1.1. Property `WfExS-backend security context > Security context > oneOf > item 0`](#pattern1_oneOf_i0)
    - [1.1.1. Property `WfExS-backend security context > Security context > oneOf > item 0 > username`](#pattern1_oneOf_i0_username)
    - [1.1.2. Property `WfExS-backend security context > Security context > oneOf > item 0 > password`](#pattern1_oneOf_i0_password)
  - [1.2. Property `WfExS-backend security context > Security context > oneOf > item 1`](#pattern1_oneOf_i1)
    - [1.2.1. Property `WfExS-backend security context > Security context > oneOf > item 1 > token`](#pattern1_oneOf_i1_token)

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

| One of(Option)               |
| ---------------------------- |
| [item 0](#pattern1_oneOf_i0) |
| [item 1](#pattern1_oneOf_i1) |
|                              |

### <a name="pattern1_oneOf_i0"></a>1.1. Property `WfExS-backend security context > Security context > oneOf > item 0`

| Type                      | `object`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Property                                   | Pattern | Type   | Deprecated | Definition | Title/Description |
| ------------------------------------------ | ------- | ------ | ---------- | ---------- | ----------------- |
| + [username](#pattern1_oneOf_i0_username ) | No      | string | No         | -          | -                 |
| + [password](#pattern1_oneOf_i0_password ) | No      | string | No         | -          | -                 |
|                                            |         |        |            |            |                   |

#### <a name="pattern1_oneOf_i0_username"></a>1.1.1. Property `WfExS-backend security context > Security context > oneOf > item 0 > username`

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

#### <a name="pattern1_oneOf_i0_password"></a>1.1.2. Property `WfExS-backend security context > Security context > oneOf > item 0 > password`

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Restrictions   |   |
| -------------- | - |
| **Min length** | 0 |
|                |   |

### <a name="pattern1_oneOf_i1"></a>1.2. Property `WfExS-backend security context > Security context > oneOf > item 1`

| Type                      | `object`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Property                             | Pattern | Type   | Deprecated | Definition | Title/Description |
| ------------------------------------ | ------- | ------ | ---------- | ---------- | ----------------- |
| + [token](#pattern1_oneOf_i1_token ) | No      | string | No         | -          | -                 |
|                                      |         |        |            |            |                   |

#### <a name="pattern1_oneOf_i1_token"></a>1.2.1. Property `WfExS-backend security context > Security context > oneOf > item 1 > token`

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

----------------------------------------------------------------------------------------------------------------------------
Generated using [json-schema-for-humans](https://github.com/coveooss/json-schema-for-humans) on 2021-07-28 at 22:36:23 +0200