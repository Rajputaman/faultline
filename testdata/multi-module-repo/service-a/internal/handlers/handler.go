package handlers

import "example.com/monorepo/service-a/internal/storage"

func Handle() string {
	return storage.Read()
}
