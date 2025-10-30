# recaptcha

[![Build Status](https://travis-ci.com/nicheinc/recaptcha.svg?branch=master)](https://travis-ci.com/nicheinc/recaptcha)
[![Go Report Card](https://goreportcard.com/badge/github.com/nicheinc/recaptcha)](https://goreportcard.com/report/github.com/nicheinc/recaptcha)
[![GoDoc](https://godoc.org/github.com/nicheinc/recaptcha?status.svg)](https://godoc.org/github.com/nicheinc/recaptcha)
[![license](https://img.shields.io/github/license/nicheinc/recaptcha.svg?maxAge=2592000)](LICENSE)

> [!NOTE]
>
> This module is no longer actively maintained.

A client library for contacting the
[reCAPTCHA v3](https://developers.google.com/recaptcha/docs/v3) token
[verification endpoint](https://developers.google.com/recaptcha/docs/verify) and
validating the response.

This project is not associated with Google or the reCAPTCHA project.

## Usage

See [godoc](https://godoc.org/github.com/nicheinc/recaptcha) for more
information, or see the [example](./example) directory for a complete working
example.

```golang
// Clients are threadsafe, and should normally be created once and reused
// throughout the life of your application.
client := recaptcha.NewClient("my_secret")

// Fetch the token verification response from the reCAPTCHA endpoint.  The
// userIP is optional, and can be omitted from the request by passing an
// empty string.
response, err := client.Fetch(context.Background(), "token", "user_ip")
if err != nil {
    fmt.Printf("Error making request to reCAPTCHA endpoint: %s\n", err)
}

// Verify the response, with additional optional verification criteria.
// Verifying the hostname and action is strongly recommended, at a minimum.
if err := response.Verify(
    recaptcha.Hostname("my_hostname"),
    recaptcha.Action("my_action"),
    recaptcha.Score(.5),
); err != nil {
    fmt.Printf("Token is invalid: %s\n", err)
} else {
    fmt.Println("Token is valid")
}
```

## License

Copyright (c) 2019 Niche.com, Inc.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
