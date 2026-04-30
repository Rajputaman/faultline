module example.com/monorepo/service-a

go 1.26

require example.com/monorepo/shared v0.0.0

replace example.com/monorepo/shared => ../shared
