// Copyright © 2019 The Things Network Foundation, The Things Industries B.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ttnpb

var isEndDeviceReadFieldPaths = []string{
	"application_server_address",
	"attributes",
	"created_at",
	"description",
	"ids",
	"ids.application_ids",
	"ids.application_ids.application_id",
	"ids.dev_eui",
	"ids.device_id",
	"ids.join_eui",
	"join_server_address",
	"locations",
	"name",
	"network_server_address",
	"service_profile_id",
	"updated_at",
	"version_ids",
	"version_ids.brand_id",
	"version_ids.firmware_version",
	"version_ids.hardware_version",
	"version_ids.model_id",
}

var isEndDeviceWriteFieldPaths = []string{
	"application_server_address",
	"attributes",
	"description",
	"ids",
	"ids.dev_eui",
	"ids.join_eui",
	"join_server_address",
	"locations",
	"name",
	"network_server_address",
	"service_profile_id",
	"version_ids",
	"version_ids.brand_id",
	"version_ids.firmware_version",
	"version_ids.hardware_version",
	"version_ids.model_id",
}

// AllowedFieldMaskPathsForRPC lists the allowed field mask paths for each RPC in this API.
var AllowedFieldMaskPathsForRPC = map[string][]string{
	// Applications:
	"/ttn.lorawan.v3.ApplicationRegistry/Get":                 ApplicationFieldPathsNested,
	"/ttn.lorawan.v3.ApplicationRegistry/List":                ApplicationFieldPathsNested,
	"/ttn.lorawan.v3.ApplicationRegistry/Update":              ApplicationFieldPathsNested,
	"/ttn.lorawan.v3.EntityRegistrySearch/SearchApplications": ApplicationFieldPathsNested,

	// Application Webhook Templates:
	"/ttn.lorawan.v3.ApplicationWebhookRegistry/GetTemplate":   ApplicationWebhookTemplateFieldPathsNested,
	"/ttn.lorawan.v3.ApplicationWebhookRegistry/ListTemplates": ApplicationWebhookTemplateFieldPathsNested,

	// Application Webhooks:
	"/ttn.lorawan.v3.ApplicationWebhookRegistry/Get":  ApplicationWebhookFieldPathsNested,
	"/ttn.lorawan.v3.ApplicationWebhookRegistry/List": ApplicationWebhookFieldPathsNested,
	"/ttn.lorawan.v3.ApplicationWebhookRegistry/Set":  ApplicationWebhookFieldPathsNested,

	// Application PubSubs:
	"/ttn.lorawan.v3.ApplicationPubSubRegistry/Get":  ApplicationPubSubFieldPathsNested,
	"/ttn.lorawan.v3.ApplicationPubSubRegistry/List": ApplicationPubSubFieldPathsNested,
	"/ttn.lorawan.v3.ApplicationPubSubRegistry/Set":  ApplicationPubSubFieldPathsNested,

	// Application Links:
	"/ttn.lorawan.v3.As/GetLink": ApplicationLinkFieldPathsNested,
	"/ttn.lorawan.v3.As/SetLink": ApplicationLinkFieldPathsNested,

	// Clients:
	"/ttn.lorawan.v3.ClientRegistry/Get":                 omitFields(ClientFieldPathsNested, "secret"),
	"/ttn.lorawan.v3.ClientRegistry/List":                omitFields(ClientFieldPathsNested, "secret"),
	"/ttn.lorawan.v3.ClientRegistry/Update":              ClientFieldPathsNested,
	"/ttn.lorawan.v3.EntityRegistrySearch/SearchClients": omitFields(ClientFieldPathsNested, "secret"),

	// End Devices:
	"/ttn.lorawan.v3.AsEndDeviceRegistry/Get": {
		"formatters",
		"formatters.down_formatter",
		"formatters.down_formatter_parameter",
		"formatters.up_formatter",
		"formatters.up_formatter_parameter",
		"ids",
		"ids.application_ids",
		"ids.application_ids.application_id",
		"ids.dev_addr",
		"ids.dev_eui",
		"ids.device_id",
		"ids.join_eui",
		"pending_session",
		"pending_session.dev_addr",
		"pending_session.keys",
		"pending_session.keys.app_s_key",
		"pending_session.keys.app_s_key.key",
		"pending_session.keys.session_key_id",
		"pending_session.last_a_f_cnt_down",
		"session",
		"session.dev_addr",
		"session.keys",
		"session.keys.app_s_key",
		"session.keys.app_s_key.key",
		"session.keys.session_key_id",
		"session.last_a_f_cnt_down",
		"version_ids",
		"version_ids.brand_id",
		"version_ids.firmware_version",
		"version_ids.hardware_version",
		"version_ids.model_id",
	},
	"/ttn.lorawan.v3.AsEndDeviceRegistry/Set": {
		"formatters",
		"formatters.down_formatter",
		"formatters.down_formatter_parameter",
		"formatters.up_formatter",
		"formatters.up_formatter_parameter",
		"ids",
		"ids.application_ids",
		"ids.application_ids.application_id",
		"ids.dev_eui",
		"ids.device_id",
		"ids.join_eui",
		"session.dev_addr",
		"session.keys.app_s_key",
		"session.keys.app_s_key.key",
		"session.last_a_f_cnt_down",
		"session.keys.session_key_id",
		"version_ids",
		"version_ids.brand_id",
		"version_ids.firmware_version",
		"version_ids.hardware_version",
		"version_ids.model_id",
	},
	"/ttn.lorawan.v3.EndDeviceRegistry/Get":                    isEndDeviceReadFieldPaths,
	"/ttn.lorawan.v3.EndDeviceRegistry/List":                   isEndDeviceReadFieldPaths,
	"/ttn.lorawan.v3.EndDeviceRegistry/Update":                 isEndDeviceWriteFieldPaths,
	"/ttn.lorawan.v3.EndDeviceRegistrySearch/SearchEndDevices": isEndDeviceReadFieldPaths,
	"/ttn.lorawan.v3.JsEndDeviceRegistry/Get": {
		"application_server_address",
		"application_server_id",
		"application_server_kek_label",
		"claim_authentication_code",
		"claim_authentication_code.value",
		"claim_authentication_code.valid_to",
		"claim_authentication_code.valid_from",
		"ids",
		"ids.application_ids",
		"ids.application_ids.application_id",
		"ids.dev_addr",
		"ids.dev_eui",
		"ids.device_id",
		"ids.join_eui",
		"last_dev_nonce",
		"last_join_nonce",
		"last_rj_count_0",
		"last_rj_count_1",
		"net_id",
		"network_server_address",
		"provisioner_id",
		"provisioning_data",
		"resets_join_nonces",
		"root_keys",
		"root_keys.app_key",
		"root_keys.app_key.key",
		"root_keys.nwk_key",
		"root_keys.nwk_key.key",
		"root_keys.root_key_id",
		"used_dev_nonces",
	},
	"/ttn.lorawan.v3.JsEndDeviceRegistry/Set": {
		"application_server_address",
		"application_server_id",
		"application_server_kek_label",
		"claim_authentication_code",
		"claim_authentication_code.value",
		"claim_authentication_code.valid_to",
		"claim_authentication_code.valid_from",
		"ids",
		"ids.application_ids",
		"ids.application_ids.application_id",
		"ids.dev_eui",
		"ids.device_id",
		"ids.join_eui",
		"last_dev_nonce",
		"last_join_nonce",
		"last_rj_count_0",
		"last_rj_count_1",
		"net_id",
		"network_server_address",
		"provisioner_id",
		"provisioning_data",
		"resets_join_nonces",
		"root_keys",
		"root_keys.app_key",
		"root_keys.app_key.key",
		"root_keys.nwk_key",
		"root_keys.nwk_key.key",
		"root_keys.root_key_id",
		"used_dev_nonces",
	},
	"/ttn.lorawan.v3.NsEndDeviceRegistry/Get": {
		"battery_percentage",
		"created_at",
		"downlink_margin",
		"frequency_plan_id",
		"ids",
		"ids.application_ids",
		"ids.application_ids.application_id",
		"ids.dev_addr",
		"ids.dev_eui",
		"ids.device_id",
		"ids.join_eui",
		"lorawan_phy_version",
		"lorawan_version",
		"mac_settings",
		"mac_settings.adr_margin",
		"mac_settings.class_b_timeout",
		"mac_settings.class_c_timeout",
		"mac_settings.desired_rx1_data_rate_offset",
		"mac_settings.desired_rx1_delay",
		"mac_settings.desired_rx1_delay.value",
		"mac_settings.desired_rx2_data_rate_index",
		"mac_settings.desired_rx2_data_rate_index.value",
		"mac_settings.desired_rx2_frequency",
		"mac_settings.factory_preset_frequencies",
		"mac_settings.max_duty_cycle",
		"mac_settings.max_duty_cycle.value",
		"mac_settings.ping_slot_data_rate_index",
		"mac_settings.ping_slot_data_rate_index.value",
		"mac_settings.ping_slot_frequency",
		"mac_settings.ping_slot_periodicity",
		"mac_settings.ping_slot_periodicity.value",
		"mac_settings.resets_f_cnt",
		"mac_settings.rx1_data_rate_offset",
		"mac_settings.rx1_delay",
		"mac_settings.rx1_delay.value",
		"mac_settings.rx2_data_rate_index",
		"mac_settings.rx2_data_rate_index.value",
		"mac_settings.rx2_frequency",
		"mac_settings.status_count_periodicity",
		"mac_settings.status_time_periodicity",
		"mac_settings.supports_32_bit_f_cnt",
		"mac_settings.use_adr",
		"mac_state",
		"mac_state.current_parameters",
		"mac_state.current_parameters.adr_ack_delay",
		"mac_state.current_parameters.adr_ack_limit",
		"mac_state.current_parameters.adr_data_rate_index",
		"mac_state.current_parameters.adr_nb_trans",
		"mac_state.current_parameters.adr_tx_power_index",
		"mac_state.current_parameters.beacon_frequency",
		"mac_state.current_parameters.channels",
		"mac_state.current_parameters.downlink_dwell_time",
		"mac_state.current_parameters.max_duty_cycle",
		"mac_state.current_parameters.max_eirp",
		"mac_state.current_parameters.ping_slot_data_rate_index",
		"mac_state.current_parameters.ping_slot_frequency",
		"mac_state.current_parameters.rejoin_count_periodicity",
		"mac_state.current_parameters.rejoin_time_periodicity",
		"mac_state.current_parameters.rx1_data_rate_offset",
		"mac_state.current_parameters.rx1_delay",
		"mac_state.current_parameters.rx2_data_rate_index",
		"mac_state.current_parameters.rx2_frequency",
		"mac_state.current_parameters.uplink_dwell_time",
		"mac_state.desired_parameters",
		"mac_state.desired_parameters.adr_ack_delay",
		"mac_state.desired_parameters.adr_ack_limit",
		"mac_state.desired_parameters.adr_data_rate_index",
		"mac_state.desired_parameters.adr_nb_trans",
		"mac_state.desired_parameters.adr_tx_power_index",
		"mac_state.desired_parameters.beacon_frequency",
		"mac_state.desired_parameters.channels",
		"mac_state.desired_parameters.downlink_dwell_time",
		"mac_state.desired_parameters.max_duty_cycle",
		"mac_state.desired_parameters.max_eirp",
		"mac_state.desired_parameters.ping_slot_data_rate_index",
		"mac_state.desired_parameters.ping_slot_frequency",
		"mac_state.desired_parameters.rejoin_count_periodicity",
		"mac_state.desired_parameters.rejoin_time_periodicity",
		"mac_state.desired_parameters.rx1_data_rate_offset",
		"mac_state.desired_parameters.rx1_delay",
		"mac_state.desired_parameters.rx2_data_rate_index",
		"mac_state.desired_parameters.rx2_frequency",
		"mac_state.desired_parameters.uplink_dwell_time",
		"mac_state.device_class",
		"mac_state.last_confirmed_downlink_at",
		"mac_state.last_dev_status_f_cnt_up",
		"mac_state.lorawan_version",
		"mac_state.pending_application_downlink",
		"mac_state.pending_application_downlink.class_b_c",
		"mac_state.pending_application_downlink.class_b_c.absolute_time",
		"mac_state.pending_application_downlink.class_b_c.gateways",
		"mac_state.pending_application_downlink.confirmed",
		"mac_state.pending_application_downlink.correlation_ids",
		"mac_state.pending_application_downlink.decoded_payload",
		"mac_state.pending_application_downlink.f_cnt",
		"mac_state.pending_application_downlink.f_port",
		"mac_state.pending_application_downlink.frm_payload",
		"mac_state.pending_application_downlink.priority",
		"mac_state.pending_application_downlink.session_key_id",
		"mac_state.pending_join_request",
		"mac_state.pending_join_request.cf_list",
		"mac_state.pending_join_request.cf_list.ch_masks",
		"mac_state.pending_join_request.cf_list.freq",
		"mac_state.pending_join_request.cf_list.type",
		"mac_state.pending_join_request.correlation_ids",
		"mac_state.pending_join_request.dev_addr",
		"mac_state.pending_join_request.downlink_settings",
		"mac_state.pending_join_request.downlink_settings.opt_neg",
		"mac_state.pending_join_request.downlink_settings.rx1_dr_offset",
		"mac_state.pending_join_request.downlink_settings.rx2_dr",
		"mac_state.pending_join_request.net_id",
		"mac_state.pending_join_request.payload",
		"mac_state.pending_join_request.payload.Payload",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.cf_list",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.cf_list.ch_masks",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.cf_list.freq",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.cf_list.type",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.dev_addr",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.dl_settings",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.dl_settings.opt_neg",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.dl_settings.rx1_dr_offset",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.dl_settings.rx2_dr",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.encrypted",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.join_nonce",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.net_id",
		"mac_state.pending_join_request.payload.Payload.join_accept_payload.rx_delay",
		"mac_state.pending_join_request.payload.Payload.join_request_payload",
		"mac_state.pending_join_request.payload.Payload.join_request_payload.dev_eui",
		"mac_state.pending_join_request.payload.Payload.join_request_payload.dev_nonce",
		"mac_state.pending_join_request.payload.Payload.join_request_payload.join_eui",
		"mac_state.pending_join_request.payload.Payload.mac_payload",
		"mac_state.pending_join_request.payload.Payload.mac_payload.decoded_payload",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr.dev_addr",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr.f_cnt",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr.f_ctrl",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr.f_ctrl.ack",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr.f_ctrl.adr",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr.f_ctrl.adr_ack_req",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr.f_ctrl.class_b",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr.f_ctrl.f_pending",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_hdr.f_opts",
		"mac_state.pending_join_request.payload.Payload.mac_payload.f_port",
		"mac_state.pending_join_request.payload.Payload.mac_payload.frm_payload",
		"mac_state.pending_join_request.payload.Payload.rejoin_request_payload",
		"mac_state.pending_join_request.payload.Payload.rejoin_request_payload.dev_eui",
		"mac_state.pending_join_request.payload.Payload.rejoin_request_payload.join_eui",
		"mac_state.pending_join_request.payload.Payload.rejoin_request_payload.net_id",
		"mac_state.pending_join_request.payload.Payload.rejoin_request_payload.rejoin_cnt",
		"mac_state.pending_join_request.payload.Payload.rejoin_request_payload.rejoin_type",
		"mac_state.pending_join_request.payload.m_hdr",
		"mac_state.pending_join_request.payload.m_hdr.m_type",
		"mac_state.pending_join_request.payload.m_hdr.major",
		"mac_state.pending_join_request.payload.mic",
		"mac_state.pending_join_request.raw_payload",
		"mac_state.pending_join_request.rx_delay",
		"mac_state.pending_join_request.selected_mac_version",
		"mac_state.pending_requests",
		"mac_state.ping_slot_periodicity",
		"mac_state.queued_join_accept",
		"mac_state.queued_join_accept.keys",
		"mac_state.queued_join_accept.keys.app_s_key",
		"mac_state.queued_join_accept.keys.app_s_key.key",
		"mac_state.queued_join_accept.keys.f_nwk_s_int_key",
		"mac_state.queued_join_accept.keys.f_nwk_s_int_key.key",
		"mac_state.queued_join_accept.keys.nwk_s_enc_key",
		"mac_state.queued_join_accept.keys.nwk_s_enc_key.key",
		"mac_state.queued_join_accept.keys.s_nwk_s_int_key",
		"mac_state.queued_join_accept.keys.s_nwk_s_int_key.key",
		"mac_state.queued_join_accept.keys.session_key_id",
		"mac_state.queued_join_accept.payload",
		"mac_state.queued_join_accept.request",
		"mac_state.queued_join_accept.request.cf_list",
		"mac_state.queued_join_accept.request.cf_list.ch_masks",
		"mac_state.queued_join_accept.request.cf_list.freq",
		"mac_state.queued_join_accept.request.cf_list.type",
		"mac_state.queued_join_accept.request.correlation_ids",
		"mac_state.queued_join_accept.request.dev_addr",
		"mac_state.queued_join_accept.request.downlink_settings",
		"mac_state.queued_join_accept.request.downlink_settings.opt_neg",
		"mac_state.queued_join_accept.request.downlink_settings.rx1_dr_offset",
		"mac_state.queued_join_accept.request.downlink_settings.rx2_dr",
		"mac_state.queued_join_accept.request.net_id",
		"mac_state.queued_join_accept.request.payload",
		"mac_state.queued_join_accept.request.payload.Payload",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.cf_list",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.cf_list.ch_masks",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.cf_list.freq",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.cf_list.type",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.dev_addr",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.dl_settings",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.dl_settings.opt_neg",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.dl_settings.rx1_dr_offset",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.dl_settings.rx2_dr",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.encrypted",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.join_nonce",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.net_id",
		"mac_state.queued_join_accept.request.payload.Payload.join_accept_payload.rx_delay",
		"mac_state.queued_join_accept.request.payload.Payload.join_request_payload",
		"mac_state.queued_join_accept.request.payload.Payload.join_request_payload.dev_eui",
		"mac_state.queued_join_accept.request.payload.Payload.join_request_payload.dev_nonce",
		"mac_state.queued_join_accept.request.payload.Payload.join_request_payload.join_eui",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.decoded_payload",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr.dev_addr",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr.f_cnt",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr.f_ctrl",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr.f_ctrl.ack",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr.f_ctrl.adr",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr.f_ctrl.adr_ack_req",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr.f_ctrl.class_b",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr.f_ctrl.f_pending",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_hdr.f_opts",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.f_port",
		"mac_state.queued_join_accept.request.payload.Payload.mac_payload.frm_payload",
		"mac_state.queued_join_accept.request.payload.Payload.rejoin_request_payload",
		"mac_state.queued_join_accept.request.payload.Payload.rejoin_request_payload.dev_eui",
		"mac_state.queued_join_accept.request.payload.Payload.rejoin_request_payload.join_eui",
		"mac_state.queued_join_accept.request.payload.Payload.rejoin_request_payload.net_id",
		"mac_state.queued_join_accept.request.payload.Payload.rejoin_request_payload.rejoin_cnt",
		"mac_state.queued_join_accept.request.payload.Payload.rejoin_request_payload.rejoin_type",
		"mac_state.queued_join_accept.request.payload.m_hdr",
		"mac_state.queued_join_accept.request.payload.m_hdr.m_type",
		"mac_state.queued_join_accept.request.payload.m_hdr.major",
		"mac_state.queued_join_accept.request.payload.mic",
		"mac_state.queued_join_accept.request.raw_payload",
		"mac_state.queued_join_accept.request.rx_delay",
		"mac_state.queued_join_accept.request.selected_mac_version",
		"mac_state.queued_responses",
		"mac_state.rx_windows_available",
		"max_frequency",
		"min_frequency",
		"multicast",
		"pending_session",
		"pending_session.dev_addr",
		"pending_session.keys",
		"pending_session.keys.f_nwk_s_int_key",
		"pending_session.keys.f_nwk_s_int_key.key",
		"pending_session.keys.nwk_s_enc_key",
		"pending_session.keys.nwk_s_enc_key.key",
		"pending_session.keys.s_nwk_s_int_key",
		"pending_session.keys.s_nwk_s_int_key.key",
		"pending_session.keys.session_key_id",
		"pending_session.last_conf_f_cnt_down",
		"pending_session.last_f_cnt_up",
		"pending_session.last_n_f_cnt_down",
		"power_state",
		"queued_application_downlinks",
		"recent_adr_uplinks",
		"recent_downlinks",
		"recent_uplinks",
		"session",
		"session.dev_addr",
		"session.keys",
		"session.keys.f_nwk_s_int_key",
		"session.keys.f_nwk_s_int_key.key",
		"session.keys.nwk_s_enc_key",
		"session.keys.nwk_s_enc_key.key",
		"session.keys.s_nwk_s_int_key",
		"session.keys.s_nwk_s_int_key.key",
		"session.keys.session_key_id",
		"session.last_conf_f_cnt_down",
		"session.last_f_cnt_up",
		"session.last_n_f_cnt_down",
		"session.started_at",
		"supports_class_b",
		"supports_class_c",
		"supports_join",
		"updated_at",
		"version_ids",
		"version_ids.brand_id",
		"version_ids.firmware_version",
		"version_ids.hardware_version",
		"version_ids.model_id",
	},
	"/ttn.lorawan.v3.NsEndDeviceRegistry/Set": {
		"frequency_plan_id",
		"ids",
		"ids.application_ids",
		"ids.application_ids.application_id",
		"ids.dev_eui",
		"ids.device_id",
		"ids.join_eui",
		"lorawan_phy_version",
		"lorawan_version",
		"mac_settings",
		"mac_settings.adr_margin",
		"mac_settings.class_b_timeout",
		"mac_settings.class_c_timeout",
		"mac_settings.desired_rx1_data_rate_offset",
		"mac_settings.desired_rx1_delay",
		"mac_settings.desired_rx1_delay.value",
		"mac_settings.desired_rx2_data_rate_index",
		"mac_settings.desired_rx2_data_rate_index.value",
		"mac_settings.desired_rx2_frequency",
		"mac_settings.factory_preset_frequencies",
		"mac_settings.max_duty_cycle",
		"mac_settings.max_duty_cycle.value",
		"mac_settings.ping_slot_data_rate_index",
		"mac_settings.ping_slot_data_rate_index.value",
		"mac_settings.ping_slot_frequency",
		"mac_settings.ping_slot_periodicity",
		"mac_settings.ping_slot_periodicity.value",
		"mac_settings.resets_f_cnt",
		"mac_settings.rx1_data_rate_offset",
		"mac_settings.rx1_delay",
		"mac_settings.rx1_delay.value",
		"mac_settings.rx2_data_rate_index",
		"mac_settings.rx2_data_rate_index.value",
		"mac_settings.rx2_frequency",
		"mac_settings.status_count_periodicity",
		"mac_settings.status_time_periodicity",
		"mac_settings.supports_32_bit_f_cnt",
		"mac_settings.use_adr",
		"mac_state.device_class",
		"mac_state.lorawan_version",
		"mac_state.ping_slot_periodicity",
		"max_frequency",
		"min_frequency",
		"multicast",
		"session.dev_addr",
		"session.keys.f_nwk_s_int_key",
		"session.keys.f_nwk_s_int_key.key",
		"session.keys.nwk_s_enc_key",
		"session.keys.nwk_s_enc_key.key",
		"session.keys.s_nwk_s_int_key",
		"session.keys.s_nwk_s_int_key.key",
		"session.keys.session_key_id",
		"session.last_conf_f_cnt_down",
		"session.last_f_cnt_up",
		"session.last_n_f_cnt_down",
		"session.started_at",
		"supports_class_b",
		"supports_class_c",
		"supports_join",
		"version_ids",
		"version_ids.brand_id",
		"version_ids.firmware_version",
		"version_ids.hardware_version",
		"version_ids.model_id",
	},

	// Gateways:
	"/ttn.lorawan.v3.EntityRegistrySearch/SearchGateways": GatewayFieldPathsNested,
	"/ttn.lorawan.v3.GatewayRegistry/Get":                 GatewayFieldPathsNested,
	"/ttn.lorawan.v3.GatewayRegistry/List":                GatewayFieldPathsNested,
	"/ttn.lorawan.v3.GatewayRegistry/Update":              GatewayFieldPathsNested,

	// Organizations:
	"/ttn.lorawan.v3.OrganizationRegistry/Get":                 OrganizationFieldPathsNested,
	"/ttn.lorawan.v3.OrganizationRegistry/List":                OrganizationFieldPathsNested,
	"/ttn.lorawan.v3.OrganizationRegistry/Update":              OrganizationFieldPathsNested,
	"/ttn.lorawan.v3.EntityRegistrySearch/SearchOrganizations": OrganizationFieldPathsNested,

	// Users:
	"/ttn.lorawan.v3.UserRegistry/Get":                 omitFields(UserFieldPathsNested, "password", "temporary_password"),
	"/ttn.lorawan.v3.UserRegistry/Update":              omitFields(UserFieldPathsNested, "password", "password_updated_at"),
	"/ttn.lorawan.v3.EntityRegistrySearch/SearchUsers": omitFields(UserFieldPathsNested, "password", "temporary_password"),
}

func omitFields(fields []string, fieldsToOmit ...string) []string {
	out := make([]string, 0, len(fields))
nextField:
	for _, field := range fields {
		for _, fieldToOmit := range fieldsToOmit {
			if field == fieldToOmit {
				continue nextField
			}
		}
		out = append(out, field)
	}
	return out
}