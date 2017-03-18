package radiusauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/boltdb/bolt"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Hash []byte    `json:"hash"`
	TTL  time.Time `json:"ttl"`
}

func cachecheck(r RADIUS, username string, password string) (bool, error) {
	cached, err := cacheseek(r, username, password)
	if err != nil {
		return false, err
	}
	if cached {
		return true, nil
	}
	return false, nil
}

func cachewrite(r RADIUS, username string, password string) (bool, error) {
	db := r.db
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		crypt, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		u := user{crypt, time.Now().UTC()}
		val, _ := json.Marshal(u)

		err := b.Put([]byte(username), val)
		return err
	})
	return false, nil
}

func cacheseek(r RADIUS, username string, password string) (bool, error) {

	db := r.db
	u := user{}

	// Look for username in BoltDB cache
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(username))
		// If usenrame (key) not found
		if v == nil {
			err := fmt.Sprintf("User: %s NOT FOUND in cache\n", username)
			return errors.New(err)
		}
		fmt.Printf("User: %s found with pass %s\n", username, v)

		json.Unmarshal(v, &u)

		// Compare provided Basic Auth password to cached bcrypt Hash
		// if different error
		err2 := bcrypt.CompareHashAndPassword(u.Hash, []byte(password))
		if err2 != nil {
			return errors.New("User password hash DOES NOT match, force RADIUS auth")
		}

		return nil
	})
	// if username not found return false, and err
	if err != nil {
		return false, err
	}

	t1 := u.TTL
	age := time.Since(t1)
	fmt.Println(age)
	if age > r.Config.cachetimeout {
		delerr := cachedelete(r, username)
		fmt.Println("DELCACHE called ****")
		if delerr != nil {
			panic(err)
		}
		return false, errors.New("Cache entry has expired, force RADIUS auth")
	}

	if err != nil {
		return false, err
	}
	return true, nil
}

func cachedelete(r RADIUS, username string) error {
	db := r.db
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		err := b.Delete([]byte(username))
		// If usenrame (key) not found
		if err == nil {
			err := fmt.Sprintf("User: %s NOT FOUND in cache\n", username)
			return errors.New(err)
			// return err
		}
		fmt.Printf("User: %s deleted from cache\n", username)
		return nil
	})
	return nil
}

func cachepurge(db *bolt.DB) (int, error) {
	var count int
	u := user{}
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		if err := b.ForEach(func(k, v []byte) error {
			json.Unmarshal(v, &u)
			age := time.Since(u.TTL)
			if age > 10*time.Minute {
				b.Delete(k)
				count++
			}
			return nil
		}); err != nil {
			return err
		}
		return nil
	})
	return count, err
}
