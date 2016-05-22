package aws

import (
	"fmt"
	"log"
	"sort"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceAwsAvailabilityZones() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceAwsAvailabilityZonesRead,

		Schema: map[string]*schema.Schema{
			"states": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			"names": &schema.Schema{
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataSourceAwsAvailabilityZonesRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	req := &ec2.DescribeAvailabilityZonesInput{}

	statesI := d.Get("states").(*schema.Set).List()
	if len(statesI) > 0 {
		filters := make([]*ec2.Filter, 1)
		filters[0] = &ec2.Filter{
			Name:   aws.String("state"),
			Values: make([]*string, len(statesI)),
		}
		for i, stateI := range statesI {
			filters[0].Values[i] = aws.String(stateI.(string))
		}
	}

	log.Printf("[DEBUG] DescribeAvailabilityZones %#v\n", req)
	resp, err := conn.DescribeAvailabilityZones(req)
	if err != nil {
		return err
	}
	if resp == nil || len(resp.AvailabilityZones) == 0 {
		return fmt.Errorf("no matching AZs found")
	}

	names := make([]string, len(resp.AvailabilityZones))

	for i, az := range resp.AvailabilityZones {
		names[i] = *az.ZoneName
	}

	sort.Strings(names)

	d.SetId("-")
	d.Set("names", names)

	return nil
}
