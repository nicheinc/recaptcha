# recaptcha

A client library for contacting the [reCAPTCHA
v3](https://developers.google.com/recaptcha/docs/v3) token [verification
endpoint](https://developers.google.com/recaptcha/docs/verify) and validating
the response.

This project is not associated with Google or the reCAPTCHA project.

## Usage

See the [documentation](https://godoc.org/github.com/nicheinc/recaptcha) for
more information.

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
