# example

Example application that shows how to use this library in conjunction with the
client-side javascript library to verify reCAPTCHA v3 tokens. Also useful for
generating example tokens for testing purposes (in which case, you must access
it via the correct domain, and use the `-action` flag to set the appropriate
action). You must provide your secret key and site key, at a minimum, for this
example to work.

## Usage

```
Usage of example:
  -action string
        expected action (default "example")
  -hostname string
        expected hostname (default "localhost")
  -port int
        Port to run example server on (default 80)
  -score float
        minimum score threshold (default 0.5)
  -secret-key string
        reCAPTCHA secret key
  -site-key string
        reCAPTCHA site key
```

## License

Copyright (c) 2019 Niche.com, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
