package recaptcha_test

import (
	"context"
	"fmt"
	"log"

	"github.com/nicheinc/recaptcha"
)

func Example() {
	// Clients are threadsafe, and should normally be created once and reused
	// throughout the life of your application.
	client := recaptcha.NewClient("my_secret")

	// Fetch the token verification response from the reCAPTCHA endpoint.
	response, err := client.Fetch(context.Background(), "token", "user_ip")
	if err != nil {
		log.Fatal(err)
	}

	// Verify the response, with optional additional verification criteria.
	// Verifying the hostname and action is strongly recommended, at a minimum.
	if err := response.Verify(
		recaptcha.Hostname("my_hostname"),
		recaptcha.Action("my_action"),
		recaptcha.Score(.5),
	); err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Token is valid")
	}
}
