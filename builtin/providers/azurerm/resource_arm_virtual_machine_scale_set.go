package azurerm

import (
	"bytes"
	"fmt"
	"log"
	"net/http"

	"time"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceArmVirtualMachineScaleSet() *schema.Resource {
	return &schema.Resource{
		Create: resourceArmVirtualMachineScaleSetCreate,
		Read:   resourceArmVirtualMachineScaleSetRead,
		Update: resourceArmVirtualMachineScaleSetCreate,
		Delete: resourceArmVirtualMachineScaleSetDelete,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"location": &schema.Schema{
				Type:      schema.TypeString,
				Required:  true,
				ForceNew:  true,
				StateFunc: azureRMNormalizeLocation,
			},

			"resource_group_name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"sku": &schema.Schema{
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"tier": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},

						"capacity": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},
					},
				},
				Set: resourceArmVirtualMachineScaleSetSkuHash,
			},

			"upgrade_policy_mode": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			"virtual_machine_os_profile": &schema.Schema{
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"computer_name_prefix": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"admin_username": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"admin_password": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"custom_data": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
				Set: resourceArmVirtualMachineScaleSetsOsProfileHash,
			},

			"virtual_machine_os_profile_secrets": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"source_vault_id": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"vault_certificates": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"certificate_url": &schema.Schema{
										Type:     schema.TypeString,
										Required: true,
									},
									"certificate_store": &schema.Schema{
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
					},
				},
			},

			"virtual_machine_os_profile_linux_config": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"disable_password_authentication": &schema.Schema{
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
						"ssh_keys": &schema.Schema{
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"path": &schema.Schema{
										Type:     schema.TypeString,
										Required: true,
									},
									"key_data": &schema.Schema{
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
					},
				},
				Set: resourceArmVirtualMachineScaleSetOsProfileLinuxConfigHash,
			},

			"virtual_machine_network_profile": &schema.Schema{
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"primary": &schema.Schema{
							Type:     schema.TypeBool,
							Required: true,
						},

						"ip_configuration": &schema.Schema{
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": &schema.Schema{
										Type:     schema.TypeString,
										Required: true,
									},

									"subnet_id": &schema.Schema{
										Type:     schema.TypeString,
										Required: true,
									},

									"load_balancer_backend_address_pool_ids": &schema.Schema{
										Type:     schema.TypeSet,
										Optional: true,
										Computed: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Set:      schema.HashString,
									},
								},
							},
						},
					},
				},
				Set: resourceArmVirtualMachineScaleSetNetworkConfigurationHash,
			},

			"virtual_machine_storage_profile_os_disk": &schema.Schema{
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"image": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},

						"vhd_containers": &schema.Schema{
							Type:     schema.TypeSet,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set:      schema.HashString,
						},

						"caching": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"os_type": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},

						"create_option": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Set: resourceArmVirtualMachineScaleSetStorageProfileOsDiskHash,
			},

			"virtual_machine_storage_profile_image_reference": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"publisher": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"offer": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"sku": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"version": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Set: resourceArmVirtualMachineScaleSetStorageProfileImageReferenceHash,
			},

			"tags": tagsSchema(),
		},
	}
}

func resourceArmVirtualMachineScaleSetCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient)
	vmScaleSetClient := client.vmScaleSetClient

	log.Printf("[INFO] preparing arguments for Azure ARM Virtual Machine Scale Set creation.")

	name := d.Get("name").(string)
	location := d.Get("location").(string)
	resGroup := d.Get("resource_group_name").(string)
	tags := d.Get("tags").(map[string]interface{})

	sku, err := expandVirtualMachineScaleSetPlan(d)
	if err != nil {
		return err
	}

	storageProfile := compute.VirtualMachineScaleSetStorageProfile{}
	osDisk, err := expandAzureRMVirtualMachineScaleSetsStorageProfileOsDisk(d)
	if err != nil {
		return err
	}
	storageProfile.OsDisk = osDisk
	if _, ok := d.GetOk("virtual_machine_storage_profile_image_reference"); ok {
		imageRef, err := expandAzureRmVirtualMachineScaleSetStorageProfileImageReference(d)
		if err != nil {
			return err
		}
		storageProfile.ImageReference = imageRef
	}

	osProfile, err := expandAzureRMVirtualMachineScaleSetsOsProfile(d)
	if err != nil {
		return err
	}

	updatePolicy := d.Get("upgrade_policy_mode").(string)
	scaleSetProps := compute.VirtualMachineScaleSetProperties{
		UpgradePolicy: &compute.UpgradePolicy{
			Mode: compute.UpgradeMode(updatePolicy),
		},
		VirtualMachineProfile: &compute.VirtualMachineScaleSetVMProfile{
			NetworkProfile: expandAzureRmVirtualMachineScaleSetNetworkProfile(d),
			StorageProfile: &storageProfile,
			OsProfile:      osProfile,
		},
	}

	scaleSetParams := compute.VirtualMachineScaleSet{
		Name:       &name,
		Location:   &location,
		Tags:       expandTags(tags),
		Sku:        sku,
		Properties: &scaleSetProps,
	}
	resp, vmErr := vmScaleSetClient.CreateOrUpdate(resGroup, name, scaleSetParams)
	if vmErr != nil {
		return vmErr
	}

	d.SetId(*resp.ID)

	log.Printf("[DEBUG] Waiting for Virtual Machine ScaleSet (%s) to become available", name)
	stateConf := &resource.StateChangeConf{
		Pending:    []string{"Creating", "Updating"},
		Target:     []string{"Succeeded"},
		Refresh:    virtualMachineScaleSetStateRefreshFunc(client, resGroup, name),
		Timeout:    20 * time.Minute,
		MinTimeout: 10 * time.Second,
	}
	if _, err := stateConf.WaitForState(); err != nil {
		return fmt.Errorf("Error waiting for Virtual Machine Scale Set (%s) to become available: %s", name, err)
	}

	return resourceArmVirtualMachineScaleSetRead(d, meta)
}

func resourceArmVirtualMachineScaleSetRead(d *schema.ResourceData, meta interface{}) error {
	vmScaleSetClient := meta.(*ArmClient).vmScaleSetClient

	id, err := parseAzureResourceID(d.Id())
	if err != nil {
		return err
	}
	resGroup := id.ResourceGroup
	name := id.Path["virtualMachineScaleSets"]

	resp, err := vmScaleSetClient.Get(resGroup, name)
	if err != nil {
		return fmt.Errorf("Error making Read request on Azure Virtual Machine Scale Set %s: %s", name, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		log.Printf("[INFO] AzureRM Virtual Machine Scale Set (%s) Not Found. Removing from State", name)
		d.SetId("")
		return nil
	}

	d.Set("location", resp.Location)
	d.Set("name", resp.Name)

	if err := d.Set("sku", flattenAzureRmVirtualMachineScaleSetSku(resp.Sku)); err != nil {
		return fmt.Errorf("[DEBUG] Error setting Virtual Machine Scale Set Sku error: %#v", err)
	}

	d.Set("upgrade_policy_mode", resp.Properties.UpgradePolicy.Mode)

	if err := d.Set("virtual_machine_os_profile", schema.NewSet(resourceArmVirtualMachineScaleSetsOsProfileHash, flattenAzureRMVirtualMachineScaleSetOsProfile(resp.Properties.VirtualMachineProfile.OsProfile))); err != nil {
		return fmt.Errorf("[DEBUG] Error setting Virtual Machine Scale Set OS Profile error: %#v", err)
	}
	return nil
}

func flattenAzureRMVirtualMachineScaleSetOsProfile(profile *compute.VirtualMachineScaleSetOSProfile) []interface{} {
	result := make(map[string]interface{})
	result["computer_name_prefix"] = *profile.ComputerNamePrefix
	//result["admin_username"] = *profile.AdminUsername
	//
	//if *profile.CustomData != "" {
	//	result["custom_data"] = *profile.CustomData
	//}

	return []interface{}{result}
}

func flattenAzureRmVirtualMachineScaleSetSku(sku *compute.Sku) []interface{} {
	result := make(map[string]interface{})
	result["name"] = *sku.Name
	result["capacity"] = *sku.Capacity

	if *sku.Tier != "" {
		result["tier"] = *sku.Tier
	}

	return []interface{}{result}
}

func resourceArmVirtualMachineScaleSetDelete(d *schema.ResourceData, meta interface{}) error {
	vmScaleSetClient := meta.(*ArmClient).vmScaleSetClient

	id, err := parseAzureResourceID(d.Id())
	if err != nil {
		return err
	}
	resGroup := id.ResourceGroup
	name := id.Path["virtualMachineScaleSets"]

	_, err = vmScaleSetClient.Delete(resGroup, name)

	return err
}

func virtualMachineScaleSetStateRefreshFunc(client *ArmClient, resourceGroupName string, scaleSetName string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		res, err := client.vmScaleSetClient.Get(resourceGroupName, scaleSetName)
		if err != nil {
			return nil, "", fmt.Errorf("Error issuing read request in virtualMachineScaleSetStateRefreshFunc to Azure ARM for Virtual Machine Scale Set '%s' (RG: '%s'): %s", scaleSetName, resourceGroupName, err)
		}

		return res, *res.Properties.ProvisioningState, nil
	}
}

func resourceArmVirtualMachineScaleSetStorageProfileImageReferenceHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["publisher"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["offer"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["sku"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["version"].(string)))

	return hashcode.String(buf.String())
}

func resourceArmVirtualMachineScaleSetSkuHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
	if m["tier"] != nil {
		buf.WriteString(fmt.Sprintf("%s-", m["tier"].(string)))
	}
	buf.WriteString(fmt.Sprintf("%d-", m["capacity"].(int)))

	return hashcode.String(buf.String())
}

func resourceArmVirtualMachineScaleSetStorageProfileOsDiskHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["caching"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["create_option"].(string)))
	if m["image"] != nil {
		buf.WriteString(fmt.Sprintf("%s-", m["image"].(string)))
	}
	if m["os_type"] != nil {
		buf.WriteString(fmt.Sprintf("%s-", m["os_type"].(string)))
	}

	return hashcode.String(buf.String())
}

func resourceArmVirtualMachineScaleSetNetworkConfigurationHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
	buf.WriteString(fmt.Sprintf("%t-", m["primary"].(bool)))
	return hashcode.String(buf.String())
}

func resourceArmVirtualMachineScaleSetsOsProfileHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["computer_name_prefix"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["admin_username"].(string)))
	return hashcode.String(buf.String())
}

func resourceArmVirtualMachineScaleSetOsProfileLinuxConfigHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%t-", m["disable_password_authentication"].(bool)))

	return hashcode.String(buf.String())
}

func expandVirtualMachineScaleSetPlan(d *schema.ResourceData) (*compute.Sku, error) {
	skuConfig := d.Get("sku").(*schema.Set).List()

	if len(skuConfig) != 1 {
		return nil, fmt.Errorf("Cannot specify more than one SKU.")
	}

	config := skuConfig[0].(map[string]interface{})

	name := config["name"].(string)
	tier := config["tier"].(string)
	capacity := int32(config["capacity"].(int))

	sku := &compute.Sku{
		Name:     &name,
		Capacity: &capacity,
	}

	if tier != "" {
		sku.Tier = &tier
	}

	return sku, nil
}

func expandAzureRmVirtualMachineScaleSetNetworkProfile(d *schema.ResourceData) *compute.VirtualMachineScaleSetNetworkProfile {
	scaleSetNetworkProfileConfigs := d.Get("virtual_machine_network_profile").(*schema.Set).List()
	networkProfileConfig := make([]compute.VirtualMachineScaleSetNetworkConfiguration, 0, len(scaleSetNetworkProfileConfigs))

	for _, npProfileConfig := range scaleSetNetworkProfileConfigs {
		config := npProfileConfig.(map[string]interface{})

		name := config["name"].(string)
		primary := config["primary"].(bool)

		ipConfigurationConfigs := config["ip_configuration"].([]interface{})
		ipConfigurations := make([]compute.VirtualMachineScaleSetIPConfiguration, 0, len(ipConfigurationConfigs))
		for _, ipConfigConfig := range ipConfigurationConfigs {
			ipconfig := ipConfigConfig.(map[string]interface{})
			name := ipconfig["name"].(string)
			subnetId := ipconfig["subnet_id"].(string)

			ipConfiguration := compute.VirtualMachineScaleSetIPConfiguration{
				Name: &name,
				Properties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
					Subnet: &compute.APIEntityReference{
						ID: &subnetId,
					},
				},
			}

			//if v := ipconfig["load_balancer_backend_address_pool_ids"]; v != nil {
			//
			//}

			ipConfigurations = append(ipConfigurations, ipConfiguration)
		}

		nProfile := compute.VirtualMachineScaleSetNetworkConfiguration{
			Name: &name,
			Properties: &compute.VirtualMachineScaleSetNetworkConfigurationProperties{
				Primary:          &primary,
				IPConfigurations: &ipConfigurations,
			},
		}

		networkProfileConfig = append(networkProfileConfig, nProfile)
	}

	return &compute.VirtualMachineScaleSetNetworkProfile{
		NetworkInterfaceConfigurations: &networkProfileConfig,
	}
}

func expandAzureRMVirtualMachineScaleSetsOsProfile(d *schema.ResourceData) (*compute.VirtualMachineScaleSetOSProfile, error) {
	osProfileConfigs := d.Get("virtual_machine_os_profile").(*schema.Set).List()

	if len(osProfileConfigs) != 1 {
		return nil, fmt.Errorf("Cannot specify more than one virtual_machine_os_profile.")
	}

	osProfileConfig := osProfileConfigs[0].(map[string]interface{})
	namePrefix := osProfileConfig["computer_name_prefix"].(string)
	username := osProfileConfig["admin_username"].(string)
	password := osProfileConfig["admin_password"].(string)
	customData := osProfileConfig["custom_data"].(string)

	osProfile := &compute.VirtualMachineScaleSetOSProfile{
		ComputerNamePrefix: &namePrefix,
		AdminUsername:      &username,
	}

	if password != "" {
		osProfile.AdminPassword = &password
	}

	if customData != "" {
		osProfile.CustomData = &customData
	}

	if v := osProfileConfig["virtual_machine_os_profile_secrets"]; v != nil {
		osProfile.Secrets = expandAzureRmVirtualMachineScaleSetOsProfileSecrets(d)
	}

	if v := osProfileConfig["virtual_machine_os_profile_linux_config"]; v != nil {
		linuxConfig, err := expandAzureRmVirtualMachineScaleSetOsProfileLinuxConfig(d)
		if err != nil {
			return nil, err
		}
		osProfile.LinuxConfiguration = linuxConfig
	}

	if v := osProfileConfig["virtual_machine_os_profile_windows_config"]; v != nil {
		winConfig, err := expandAzureRmVirtualMachineScaleSetOsProfileWindowsConfig(d)
		if err != nil {
			return nil, err
		}
		if winConfig != nil {
			osProfile.WindowsConfiguration = winConfig
		}
	}

	return osProfile, nil
}

func expandAzureRMVirtualMachineScaleSetsStorageProfileOsDisk(d *schema.ResourceData) (*compute.VirtualMachineScaleSetOSDisk, error) {
	osDiskConfigs := d.Get("virtual_machine_storage_profile_os_disk").(*schema.Set).List()

	if len(osDiskConfigs) != 1 {
		return nil, fmt.Errorf("Cannot specify more than one virtual_machine_storage_profile_os_disk.")
	}

	osDiskConfig := osDiskConfigs[0].(map[string]interface{})
	name := osDiskConfig["name"].(string)
	image := osDiskConfig["image"].(string)
	caching := osDiskConfig["caching"].(string)
	osType := osDiskConfig["os_type"].(string)
	createOption := osDiskConfig["create_option"].(string)

	var vhdContainers []string
	containers := osDiskConfig["vhd_containers"].(*schema.Set).List()
	for _, v := range containers {
		str := v.(string)
		vhdContainers = append(vhdContainers, str)
	}

	osDisk := &compute.VirtualMachineScaleSetOSDisk{
		Name:          &name,
		Caching:       compute.CachingTypes(caching),
		OsType:        compute.OperatingSystemTypes(osType),
		CreateOption:  compute.DiskCreateOptionTypes(createOption),
		VhdContainers: &vhdContainers,
	}

	if image != "" {
		osDisk.Image = &compute.VirtualHardDisk{
			URI: &image,
		}
	}

	return osDisk, nil

}

func expandAzureRmVirtualMachineScaleSetStorageProfileImageReference(d *schema.ResourceData) (*compute.ImageReference, error) {
	storageImageRefs := d.Get("virtual_machine_storage_profile_image_reference").(*schema.Set).List()

	if len(storageImageRefs) != 1 {
		return nil, fmt.Errorf("Cannot specify more than one virtual_machine_storage_profile_image_reference.")
	}

	storageImageRef := storageImageRefs[0].(map[string]interface{})

	publisher := storageImageRef["publisher"].(string)
	offer := storageImageRef["offer"].(string)
	sku := storageImageRef["sku"].(string)
	version := storageImageRef["version"].(string)

	return &compute.ImageReference{
		Publisher: &publisher,
		Offer:     &offer,
		Sku:       &sku,
		Version:   &version,
	}, nil
}

func expandAzureRmVirtualMachineScaleSetOsProfileLinuxConfig(d *schema.ResourceData) (*compute.LinuxConfiguration, error) {
	osProfilesLinuxConfig := d.Get("virtual_machine_os_profile_linux_config").(*schema.Set).List()

	if len(osProfilesLinuxConfig) != 1 {
		return nil, fmt.Errorf("[ERROR] Only 1 OS Profile Linux Config Can be specified for an Azure RM Virtual Machine Scale Set")
	}

	linuxConfig := osProfilesLinuxConfig[0].(map[string]interface{})
	config := &compute.LinuxConfiguration{}
	linuxKeys := linuxConfig["ssh_keys"].([]interface{})
	sshPublicKeys := make([]compute.SSHPublicKey, 0, len(linuxKeys))
	for _, key := range linuxKeys {
		sshKey := key.(map[string]interface{})
		path := sshKey["path"].(string)
		keyData := sshKey["key_data"].(string)

		sshPublicKey := compute.SSHPublicKey{
			Path:    &path,
			KeyData: &keyData,
		}

		sshPublicKeys = append(sshPublicKeys, sshPublicKey)
	}

	config.SSH = &compute.SSHConfiguration{
		PublicKeys: &sshPublicKeys,
	}

	return config, nil
}

func expandAzureRmVirtualMachineScaleSetOsProfileWindowsConfig(d *schema.ResourceData) (*compute.WindowsConfiguration, error) {
	osProfilesWindowsConfig := d.Get("virtual_machine_os_profile_windows_config").(*schema.Set).List()

	if len(osProfilesWindowsConfig) != 1 {
		return nil, fmt.Errorf("[ERROR] Only 1 OS Profile Windows Config Can be specified for an Azure RM Virtual Machine")
	}

	return nil, nil
}

func expandAzureRmVirtualMachineScaleSetOsProfileSecrets(d *schema.ResourceData) *[]compute.VaultSecretGroup {
	secretsConfig := d.Get("virtual_machine_os_profile_secrets").(*schema.Set).List()
	secrets := make([]compute.VaultSecretGroup, 0, len(secretsConfig))

	for _, secretConfig := range secretsConfig {
		config := secretConfig.(map[string]interface{})
		sourceVaultId := config["source_vault_id"].(string)

		vaultSecretGroup := compute.VaultSecretGroup{
			SourceVault: &compute.SubResource{
				ID: &sourceVaultId,
			},
		}

		if v := config["vault_certificates"]; v != nil {
			certsConfig := v.(*schema.Set).List()
			certs := make([]compute.VaultCertificate, 0, len(certsConfig))
			for _, certConfig := range certsConfig {
				config := certConfig.(map[string]interface{})

				certUrl := config["certificate_url"].(string)
				cert := compute.VaultCertificate{
					CertificateURL: &certUrl,
				}
				if v := config["certificate_store"].(string); v != "" {
					cert.CertificateStore = &v
				}

				certs = append(certs, cert)
			}
			vaultSecretGroup.VaultCertificates = &certs
		}

		secrets = append(secrets, vaultSecretGroup)
	}

	return &secrets
}
