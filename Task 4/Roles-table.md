## СТРУКТУРА РОЛЕЙ И ДОСТУПА

| Роль                |  Права роли                                                                                            | Группы пользователей              |
|---------------------|--------------------------------------------------------------------------------------------------------|----------------------------------------|
| **Администратор кластера (cluster-admins)** | Администратор кластера | sys-admin |
| **Администратор пространства имён (admins)** | Полные права на все ресурсы внутри определённого namespace (эквивалент роли admin на уровне пространства имён) | finance-admin, client-admin, housing-admin, bi-admin |
| **Привилегированный для секретов (secrets-access)** | Полный доступ (`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`) к secrets и configmaps в рамках пространств имён | finance-secrets-access, client-secrets-access, housing-secrets-access, bi-secrets-access |
| **Настройщик (conf)**   | Управление приложениями (`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`) для объектов: pods, deployments, jobs, services, configmaps, ingresses, HPA; доступ к secrets — только на чтение | finance-conf, client-conf, housing-conf, bi-conf |
| **Наблюдатель (watchers)**       | Право на просмотр (`get`, `list`, `watch`) объектов: pods, deployments, services, ingresses, configmaps, namespaces, nodes | finance-watch, client-watch, housing-watch, bi-watch |

> Также возможны дополнительные роли, которые будут назначаться ServiceAccount, но они опущены для упрощения

## Пространства имён

Система использует четыре основных пространства имён (namespace) в production среде:

`finance` - бухгалтерия</br>
`client` - группа сервисов для клиентов</br>
`housing` - группа сервисов ЖКУ</br>
`bi` -  хранилищие даннах для аналитики</br>

*Также имеются два отдельных пространства для разработки, но информация о них специально опущена в целях упрощения*

`client-dev` - пространство для разработки группа сервисов для клиентов</br>
`housing-dev` - пространство для разработки группа сервисов ЖКУ</br>

Механизм предоставления прав построен по принципу «роль × пространство имён». Каждой группе пользователей назначается соответствующая кластерная роль, чтобы через привязки выдавать роли в конкретном namespace. Примеры связей:

- Группа `finance-admin` получает права через ClusterRoleBinding, связывающий её с ClusterRole `admin` в namespace `finance`.
- Группа `client-secrets-access` получает права через отдельные ClusterRoleBinding-и, связывающие её с ClusterRole `secrets-access` в client namespace.
