package radiusauth

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

var bucketName = []byte("users")

type cachedUser struct {
	Hash []byte    `json:"hash"`
	TTL  time.Time `json:"ttl"`
}

// openCacheDB opens (or creates) the BoltDB cache file at dir/radiusauth.db.
func openCacheDB(dir string) (*bolt.DB, error) {
	path := dir + "/radiusauth.db"
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	return db, db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
}

func cacheWrite(ra RadiusAuth, username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	val, err := json.Marshal(cachedUser{Hash: hash, TTL: time.Now().UTC()})
	if err != nil {
		return err
	}
	return ra.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put([]byte(username), val)
	})
}

func cacheSeek(ra RadiusAuth, username, password string) (bool, error) {
	if ra.CacheTimeout == 0 {
		return false, fmt.Errorf("caching disabled")
	}

	var u cachedUser
	err := ra.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketName).Get([]byte(username))
		if v == nil {
			return fmt.Errorf("user %s not in cache", username)
		}
		if err := json.Unmarshal(v, &u); err != nil {
			return err
		}
		return bcrypt.CompareHashAndPassword(u.Hash, []byte(password))
	})
	if err != nil {
		return false, err
	}

	if time.Since(u.TTL) > time.Duration(ra.CacheTimeout) {
		_ = cacheDelete(ra, username)
		return false, fmt.Errorf("cache expired for %s", username)
	}

	return true, nil
}

func cacheDelete(ra RadiusAuth, username string) error {
	return ra.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Delete([]byte(username))
	})
}

// cachePurge removes entries older than timeout and returns the count deleted.
func cachePurge(db *bolt.DB, timeout time.Duration) (int, error) {
	var count int
	return count, db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		return b.ForEach(func(k, v []byte) error {
			var u cachedUser
			if err := json.Unmarshal(v, &u); err != nil {
				return nil // skip malformed entries
			}
			if time.Since(u.TTL) > timeout {
				count++
				return b.Delete(k)
			}
			return nil
		})
	})
}
