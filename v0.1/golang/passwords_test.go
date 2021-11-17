package passwords

import (
	"fmt"
	"testing"
)

type HashPasswordTestPlan []struct {
	Password string
}

type VerifyPasswordFailsTestPlan []struct {
	Password          string
	IncorrectPassword string
}

var HashPasswordPlan = HashPasswordTestPlan{
	{""},
	{"admin"},
	{"password"},
	{"1234567890"},
	{"hello, world"},
}

var PasswordFailsPlan = VerifyPasswordFailsTestPlan{
	{"", "hello, world"},
	{"admin", "1234567890"},
	{"password", "drowssap"},
	{"1234567890", "admin"},
	{"hello, world", ""},
}

var HashParamsDoubleCheck = HashParams{
	HashFunction: "argon2",
	Memory:       32 * 1024,
	Time:         3,
	Threads:      4,
	SaltLength:   32,
	KeyLength:    32,
}

func TestDefaultHashParams(t *testing.T) {
	if DefaultHashParams != HashParamsDoubleCheck {
		t.Error("Unrecognized change in default password hash params.")
	}
}

func TestHashPassword(t *testing.T) {
	for index, test := range HashPasswordPlan {
		hashedPassword, err := HashPassword(test.Password, &DefaultHashParams)
		if err != nil {
			t.Error(
				fmt.Sprintf(
					"Error hashing password!\n%d: %s",
					index,
					test.Password,
				),
			)
			continue
		}

		if test.Password == hashedPassword.Hash {
			t.Error("Password failed to hash")
		}
	}
}

func TestVerifyPassword(t *testing.T) {
	for index, test := range HashPasswordPlan {
		hashedPasswordResults, hashedPasswordErr := HashPassword(
			test.Password,
			&DefaultHashParams,
		)
		if hashedPasswordErr != nil {
			t.Error(
				fmt.Sprintf(
					"Error hashing password!\n%d: %s",
					index,
					test.Password,
				),
			)
			continue
		}

		passwordIsValid, passwordCheckErr := VerifyPassword(
			test.Password,
			hashedPasswordResults,
		)

		if passwordCheckErr != nil {
			t.Error(
				fmt.Sprintf(
					"Error validating password!\n%d: %s",
					index,
					test.Password,
				),
			)
			continue
		}

		if !passwordIsValid {
			t.Error(
				fmt.Sprintf(
					"Assymetric password matching failed:\n%d: %s",
					index,
					test.Password,
				),
			)
		}
	}
}

func TestVerifyPasswordFails(t *testing.T) {
	for index, test := range PasswordFailsPlan {
		hashedPasswordResults, hashedPasswordErr := HashPassword(
			test.Password,
			&DefaultHashParams,
		)
		if hashedPasswordErr != nil {
			t.Error(
				fmt.Sprintf(
					"Error hashing password!\n%d: %s",
					index,
					test.Password,
				),
			)
			continue
		}

		passwordIsValid, passwordCheckErr := VerifyPassword(
			test.IncorrectPassword,
			hashedPasswordResults,
		)

		if passwordCheckErr != nil {
			t.Error(
				fmt.Sprintf(
					"Error validating password!\n%d: %s",
					index,
					test.Password,
				),
			)
			continue
		}

		if passwordIsValid {
			t.Error(
				fmt.Sprintf(
					"Assymetric password matching succeeded where it shouldn't:\n%d: %s",
					index,
					test.Password,
				),
			)
		}
	}
}
