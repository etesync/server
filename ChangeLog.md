# Changelog

## Version 0.8.3
- Fix compatibility with latest fastapi

## Version 0.8.2
- Update dependencies again

## Version 0.8.1
* Fix Error `404 Not Found` for Static Files
* Fix Django 3.2 warnings
* Update dependencies while (keep Django 3.2 LTS)

## Version 0.8.0
* Update django dep.
* Fix issue with comparing ports in hostname verification with self-hosted servers.
* Fix sendfile settings to be more correct.
* Improve easy config (make it clear media_root needs to be set)
* Handle stoken being the empty string
* Fix mysql/mariadb support
* Switch to FastAPI for the server component

## Version 0.7.0
* Chunks: improve the chunk download endpoint to use sendfile extensions
* Chunks: support not passing chunk content if exists
* Chunks: fix chunk uploading media type to accept everything
* Gracefull handle uploading the same revision
* Pass generic context to callbacks instead of the whole view
* Fix handling of some validation errors

## Version 0.6.1
* Collection: save the UID on the model to use the db for enforcing uniqueness

## Version 0.6.0
* Fix stoken calculation performance - was VERY slow in some rare cases
* Fix issues with host verification failing with a custom port - part 2

## Version 0.5.3
* Add missing migration

## Version 0.5.2
* Fix issues with host verification failing with a custom port
* Add env variable to change configuration file path.
* Change user creation to not ask for a password (and clarify the readme).

## Version 0.5.1
* Enforce collections to always have a collection type set
* Collection saving: add another verification for collection UID uniqueness.

## Version 0.5.0
* First Etebase-server release (was EteSync-server before)
