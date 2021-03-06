package radiusauth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/boltdb/bolt"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Hash []byte    `json:"hash"`
	TTL  time.Time `json:"ttl"`
}

func cacheWrite(r RADIUS, username string, password string) error {
	db := r.db
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		crypt, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		u := user{crypt, time.Now().UTC()}
		val, _ := json.Marshal(u)

		err := b.Put([]byte(username), val)
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

func cacheSeek(r RADIUS, username string, password string) (bool, error) {

	db := r.db
	u := user{}

	if r.Config.cachetimeout == 0 {
		return false, fmt.Errorf("[radiusauth] User caching disabled, force RADIUS auth")
	}
	// Look for username in BoltDB cache
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(username))
		// If usenrame (key) not found
		if v == nil {
			return fmt.Errorf("[radiusauth] User: %s NOT FOUND in cache", username)
		}
		// Unmarshal value v into user{hash, ttl}
		json.Unmarshal(v, &u)

		// Compare provided Basic Auth password to cached bcrypt Hash
		// if different error
		err2 := bcrypt.CompareHashAndPassword(u.Hash, []byte(password))
		if err2 != nil {
			return fmt.Errorf("[radiusauth] bcrypt hash DOES NOT match for %s, force RADIUS auth", username)
		}
		return nil
	})
	// if username not found or password mismatch in cache return false, and err
	if err != nil {
		return false, err
	}

	// Check if cache entry is older than cachetimeout
	// If entry is older, delete entry and return false
	//  to force a new RADIUS authentication
	age := time.Since(u.TTL)
	if age > r.Config.cachetimeout {
		delerr := cacheDelete(r, username)
		if delerr != nil {
			panic(err)
		}
		return false, fmt.Errorf("[radiusauth] cache expired for %s, force RADIUS auth", username)
	}

	// Handle any other errors
	if err != nil {
		return false, err
	}
	return true, nil
}

func cacheDelete(r RADIUS, username string) error {
	db := r.db
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		err := b.Delete([]byte(username))
		// If username (key) not found
		if err == nil {
			return fmt.Errorf("[radiusauth] DELETE User: %s NOT FOUND in cache", username)
		}
		return nil
	})
	return nil
}

func cachePurge(db *bolt.DB) (int, error) {
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
