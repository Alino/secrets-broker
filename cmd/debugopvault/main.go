package main

import (
	"fmt"
	"os"

	"github.com/vaultcore/secrets-broker/third_party/opvault"
)

func main() {
	dir := os.Args[1]
	v, err := opvault.Open(dir)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	names, _ := v.ProfileNames()
	fmt.Println("profiles:", names)
	p, err := v.Profile("default")
	if err != nil {
		fmt.Println("profile:", err)
		return
	}
	if err := p.Unlock("correct horse battery staple"); err != nil {
		fmt.Println("unlock:", err)
		return
	}
	fmt.Println("unlock OK")
	items, err := p.Items()
	fmt.Println("items:", len(items), "err:", err)
	for _, it := range items {
		fmt.Printf("item: title=%q trashed=%v\n", it.Title(), it.Trashed())
		d, err := it.Detail()
		if err != nil {
			fmt.Println("  detail err:", err)
			continue
		}
		for _, f := range d.Fields() {
			fmt.Printf("  field name=%q type=%q desig=%q value-len=%d\n", f.Name(), f.Type(), f.Designation(), len(f.Value()))
		}
	}
}
