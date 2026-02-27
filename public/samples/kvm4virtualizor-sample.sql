-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Feb 14, 2026 at 01:20 PM
-- Server version: 5.5.62
-- PHP Version: 7.4.33

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `virtualizor`
--

-- --------------------------------------------------------

--
-- Table structure for table `admin_acl`
--

CREATE TABLE `admin_acl` (
  `aclid` int(11) NOT NULL,
  `acl_name` varchar(25) NOT NULL,
  `act_cluster_statistics` tinyint(4) NOT NULL,
  `act_cluster_resources` tinyint(4) NOT NULL,
  `act_statistics` tinyint(4) NOT NULL,
  `act_server_statistics` tinyint(4) NOT NULL,
  `act_vs` tinyint(4) NOT NULL,
  `act_vsresources` tinyint(4) NOT NULL,
  `act_editvs` tinyint(4) NOT NULL,
  `act_suspendvs` tinyint(4) NOT NULL,
  `act_unsuspendvs` tinyint(4) NOT NULL,
  `act_deletevs` tinyint(4) NOT NULL,
  `act_startvs` tinyint(4) NOT NULL,
  `act_stopvs` tinyint(4) NOT NULL,
  `act_restartvs` tinyint(4) NOT NULL,
  `act_poweroffvs` tinyint(4) NOT NULL,
  `act_addvs` tinyint(4) NOT NULL,
  `act_rebuildvs` tinyint(4) NOT NULL,
  `act_vnc` tinyint(4) NOT NULL,
  `act_migrate` tinyint(4) NOT NULL,
  `act_ippool` tinyint(4) NOT NULL,
  `act_editippool` tinyint(4) NOT NULL,
  `act_deleteippool` tinyint(4) NOT NULL,
  `act_addippool` tinyint(4) NOT NULL,
  `act_ips` tinyint(4) NOT NULL,
  `act_editips` tinyint(4) NOT NULL,
  `act_deleteips` tinyint(4) NOT NULL,
  `act_addips` tinyint(4) NOT NULL,
  `act_servers` tinyint(4) NOT NULL,
  `act_addserver` tinyint(4) NOT NULL,
  `act_editserver` tinyint(4) NOT NULL,
  `act_deleteserver` tinyint(4) NOT NULL,
  `act_rebootserver` tinyint(4) NOT NULL,
  `act_sg` tinyint(4) NOT NULL,
  `act_addsg` tinyint(4) NOT NULL,
  `act_editsg` tinyint(4) NOT NULL,
  `act_deletesg` tinyint(4) NOT NULL,
  `act_vpsbackupsettings` tinyint(4) NOT NULL,
  `act_restorevpsbackup` tinyint(4) NOT NULL,
  `act_deletevpsbackup` tinyint(4) NOT NULL,
  `act_vpsbackups` tinyint(4) NOT NULL,
  `act_backupservers` tinyint(4) NOT NULL,
  `act_editbackupservsers` tinyint(4) NOT NULL,
  `act_addbackupserver` tinyint(4) NOT NULL,
  `act_deletebackupserver` tinyint(4) NOT NULL,
  `act_plans` tinyint(4) NOT NULL,
  `act_addplan` tinyint(4) NOT NULL,
  `act_editplan` tinyint(4) NOT NULL,
  `act_deleteplan` tinyint(4) NOT NULL,
  `act_dnsplans` tinyint(4) NOT NULL,
  `act_adddnsplan` tinyint(4) NOT NULL,
  `act_editdnsplan` tinyint(4) NOT NULL,
  `act_deletednsplan` tinyint(4) NOT NULL,
  `act_users` tinyint(4) NOT NULL,
  `act_adduser` tinyint(4) NOT NULL,
  `act_edituser` tinyint(4) NOT NULL,
  `act_deleteuser` tinyint(4) NOT NULL,
  `act_ostemplates` tinyint(4) NOT NULL,
  `act_edittemplate` tinyint(4) NOT NULL,
  `act_deletetemplate` tinyint(4) NOT NULL,
  `act_os` tinyint(4) NOT NULL,
  `act_addtemplate` tinyint(4) NOT NULL,
  `act_createtemplate` tinyint(4) NOT NULL,
  `act_iso` tinyint(4) NOT NULL,
  `act_addiso` tinyint(4) NOT NULL,
  `act_editiso` tinyint(4) NOT NULL,
  `act_deleteiso` tinyint(4) NOT NULL,
  `act_mg` tinyint(4) NOT NULL,
  `act_addmg` tinyint(4) NOT NULL,
  `act_editmg` tinyint(4) NOT NULL,
  `act_deletemg` tinyint(4) NOT NULL,
  `act_config` tinyint(4) NOT NULL,
  `act_emailsettings` tinyint(4) NOT NULL,
  `act_databackup` tinyint(4) NOT NULL,
  `act_performdatabackup` tinyint(4) NOT NULL,
  `act_dldatabackup` tinyint(4) NOT NULL,
  `act_deletedatabackup` tinyint(4) NOT NULL,
  `act_adminacl` tinyint(4) NOT NULL,
  `act_add_admin_acl` tinyint(4) NOT NULL,
  `act_edit_admin_acl` tinyint(4) NOT NULL,
  `act_delete_admin_acl` tinyint(4) NOT NULL,
  `act_serverinfo` tinyint(4) NOT NULL,
  `act_licenseinfo` tinyint(4) NOT NULL,
  `act_hostname` tinyint(4) NOT NULL,
  `act_changehostname` tinyint(4) NOT NULL,
  `act_maintenance` tinyint(4) NOT NULL,
  `act_kernconfig` tinyint(4) NOT NULL,
  `act_defaultvsconf` tinyint(4) NOT NULL,
  `act_updates` tinyint(4) NOT NULL,
  `act_emailtemps` tinyint(4) NOT NULL,
  `act_editemailtemps` tinyint(4) NOT NULL,
  `act_phpmyadmin` tinyint(4) NOT NULL,
  `act_pdns` tinyint(4) NOT NULL,
  `act_addpdns` tinyint(4) NOT NULL,
  `act_editpdns` tinyint(4) NOT NULL,
  `act_deletepdns` tinyint(4) NOT NULL,
  `act_rdns` tinyint(4) NOT NULL,
  `act_managepdns` tinyint(4) NOT NULL,
  `act_importvs` tinyint(4) NOT NULL,
  `act_ssl` tinyint(4) NOT NULL,
  `act_editssl` tinyint(4) NOT NULL,
  `act_createssl` tinyint(4) NOT NULL,
  `act_serverfirewall_status` tinyint(4) NOT NULL DEFAULT '0',
  `act_firewall` tinyint(4) NOT NULL,
  `act_procs` tinyint(4) NOT NULL,
  `act_services` tinyint(4) NOT NULL,
  `act_smart_devices` tinyint(4) NOT NULL DEFAULT '0',
  `act_disk_health` tinyint(4) NOT NULL DEFAULT '0',
  `act_server_sshkeys` tinyint(4) NOT NULL DEFAULT '0',
  `act_webserver` tinyint(4) NOT NULL,
  `act_network` tinyint(4) NOT NULL,
  `act_sendmail` tinyint(4) NOT NULL,
  `act_mysqld` tinyint(4) NOT NULL,
  `act_iptables` tinyint(4) NOT NULL,
  `act_filemanager` tinyint(4) NOT NULL,
  `act_ssh` tinyint(4) NOT NULL,
  `act_logs` tinyint(4) NOT NULL,
  `act_userlogs` tinyint(4) NOT NULL,
  `act_loginlogs` tinyint(4) NOT NULL,
  `act_deletelogs` tinyint(4) NOT NULL,
  `act_deleteloginlogs` tinyint(4) NOT NULL,
  `act_deleteuserlogs` tinyint(4) NOT NULL,
  `act_recipes` tinyint(4) NOT NULL,
  `act_addrecipe` tinyint(4) NOT NULL,
  `act_editrecipe` tinyint(4) NOT NULL,
  `act_iplogs` tinyint(4) NOT NULL,
  `act_deliplogs` tinyint(4) NOT NULL,
  `act_list_distros` tinyint(4) NOT NULL DEFAULT '0',
  `act_add_distro` tinyint(4) NOT NULL DEFAULT '0',
  `act_suspend_user` tinyint(4) NOT NULL,
  `act_unsuspend_user` tinyint(4) NOT NULL,
  `act_backup_plans` tinyint(4) NOT NULL DEFAULT '0',
  `act_addbackup_plan` tinyint(4) NOT NULL DEFAULT '0',
  `act_editbackup_plan` tinyint(4) NOT NULL DEFAULT '0',
  `act_deletebackup_plan` tinyint(4) NOT NULL DEFAULT '0',
  `act_haproxy` tinyint(4) NOT NULL DEFAULT '0',
  `act_twofactauth` tinyint(4) NOT NULL DEFAULT '0',
  `act_euiso` tinyint(4) NOT NULL DEFAULT '0',
  `act_orphaneddisk` tinyint(4) NOT NULL DEFAULT '0',
  `act_deleteorphaneddisk` tinyint(4) NOT NULL DEFAULT '0',
  `act_synciso` tinyint(4) NOT NULL DEFAULT '0',
  `act_syncostemplate` tinyint(4) NOT NULL DEFAULT '0',
  `act_storage` tinyint(4) NOT NULL DEFAULT '0',
  `act_addstorage` tinyint(4) NOT NULL DEFAULT '0',
  `act_editstorage` tinyint(4) NOT NULL DEFAULT '0',
  `act_deletestorage` tinyint(4) NOT NULL DEFAULT '0',
  `act_manageserver` tinyint(4) NOT NULL DEFAULT '0',
  `act_ha` tinyint(4) NOT NULL DEFAULT '0',
  `act_multivirt` tinyint(4) NOT NULL DEFAULT '0',
  `act_webuzo` tinyint(4) NOT NULL DEFAULT '0',
  `act_billing` tinyint(4) NOT NULL DEFAULT '0',
  `act_resource_pricing` tinyint(4) NOT NULL DEFAULT '0',
  `act_invoices` tinyint(4) NOT NULL DEFAULT '0',
  `act_transactions` tinyint(4) NOT NULL DEFAULT '0',
  `act_addinvoice` tinyint(4) NOT NULL DEFAULT '0',
  `act_addtransaction` tinyint(4) NOT NULL DEFAULT '0',
  `act_add_dnsrecord` tinyint(4) NOT NULL DEFAULT '0',
  `act_terminal` tinyint(4) NOT NULL DEFAULT '0',
  `act_volumes` tinyint(4) NOT NULL DEFAULT '0',
  `act_list_api` tinyint(4) NOT NULL DEFAULT '0',
  `act_create_api` tinyint(4) NOT NULL DEFAULT '0',
  `act_api_credential_edit` tinyint(4) NOT NULL DEFAULT '0',
  `act_show_api_log` tinyint(4) NOT NULL DEFAULT '0',
  `act_load_balancer` tinyint(4) NOT NULL DEFAULT '0',
  `act_manage_load_balancer` tinyint(4) NOT NULL DEFAULT '0',
  `act_sso` tinyint(4) NOT NULL DEFAULT '0',
  `act_export_as_csv` tinyint(4) NOT NULL DEFAULT '0',
  `act_firewall_plans` tinyint(4) NOT NULL DEFAULT '0',
  `act_addfirewall_plan` tinyint(4) NOT NULL DEFAULT '0',
  `act_editfirewall_plan` tinyint(4) NOT NULL DEFAULT '0',
  `act_deletefirewall_plan` tinyint(4) NOT NULL DEFAULT '0',
  `act_vpsfirewallconfig` tinyint(4) NOT NULL DEFAULT '0',
  `act_passthrough` tinyint(4) NOT NULL DEFAULT '0',
  `act_addpassthrough` tinyint(4) NOT NULL DEFAULT '0',
  `act_editpassthrough` tinyint(4) NOT NULL DEFAULT '0',
  `act_deletepassthrough` tinyint(4) NOT NULL DEFAULT '0',
  `act_kyc_setting` tinyint(4) NOT NULL DEFAULT '0',
  `act_edit_kyc` tinyint(4) NOT NULL DEFAULT '0',
  `act_delete_kyc` tinyint(4) NOT NULL DEFAULT '0',
  `act_list_kyc` tinyint(4) NOT NULL DEFAULT '0',
  `act_log_rotation` tinyint(4) NOT NULL DEFAULT '0',
  `serverfirewall_status` tinyint(4) NOT NULL DEFAULT '0',
  `act_storageusage` tinyint(4) NOT NULL DEFAULT '0',
  `act_mail` tinyint(4) NOT NULL DEFAULT '0',
  `act_user_notice` tinyint(4) NOT NULL DEFAULT '0',
  `act_add_user_notice` tinyint(4) NOT NULL DEFAULT '0',
  `act_edit_user_notice` tinyint(4) NOT NULL DEFAULT '0',
  `act_tax_rules` tinyint(4) NOT NULL DEFAULT '0',
  `act_csf` tinyint(4) NOT NULL DEFAULT '0',
  `act_vps_stats` tinyint(4) NOT NULL DEFAULT '0',
  `act_serverloads` tinyint(4) NOT NULL DEFAULT '0',
  `act_vsbandwidth` tinyint(4) NOT NULL DEFAULT '0',
  `act_server_stats` tinyint(4) NOT NULL DEFAULT '0',
  `act_performance` tinyint(4) NOT NULL DEFAULT '0',
  `act_support_access` tinyint(4) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `admin_notes`
--

CREATE TABLE `admin_notes` (
  `noteid` int(10) NOT NULL,
  `uid` int(10) NOT NULL,
  `title` varchar(128) NOT NULL,
  `content` text NOT NULL,
  `time` int(10) NOT NULL,
  `type` tinyint(1) NOT NULL,
  `done` int(10) NOT NULL DEFAULT '-1'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `api`
--

CREATE TABLE `api` (
  `idapi` int(10) NOT NULL,
  `uid` int(10) NOT NULL DEFAULT '0',
  `apikey` varchar(50) NOT NULL DEFAULT '',
  `apipass` varchar(50) NOT NULL DEFAULT '',
  `ip` text,
  `logging` int(11) DEFAULT '0',
  `data` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `api_log`
--

CREATE TABLE `api_log` (
  `id` int(20) NOT NULL,
  `vpsid` int(20) NOT NULL,
  `user_type` int(4) NOT NULL,
  `api_id` int(25) NOT NULL,
  `uid` int(20) NOT NULL,
  `from_ip` varchar(50) NOT NULL,
  `action` varchar(20) NOT NULL,
  `time` int(10) NOT NULL,
  `status` int(11) NOT NULL,
  `data` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `backups`
--

CREATE TABLE `backups` (
  `bkid` int(10) NOT NULL,
  `bkup_uuid` varchar(16) NOT NULL,
  `vpsid` int(10) NOT NULL,
  `vps_name` text NOT NULL,
  `serid` int(10) NOT NULL,
  `bid` int(10) NOT NULL,
  `bkply_id` int(10) NOT NULL,
  `parent_bkply_id` int(10) DEFAULT NULL,
  `type` varchar(10) NOT NULL,
  `is_legacy_bkp` int(5) DEFAULT '0',
  `vps_uuid` varchar(100) NOT NULL,
  `hostname` varchar(255) NOT NULL,
  `dir` text NOT NULL,
  `disk_num` int(10) DEFAULT '0',
  `filepath` text NOT NULL,
  `filename` text NOT NULL,
  `bkply_filepath` varchar(255) NOT NULL,
  `htime` varchar(255) NOT NULL,
  `time` int(10) NOT NULL,
  `date` int(10) DEFAULT '0',
  `bitmap` varchar(255) DEFAULT NULL,
  `size` bigint(15) NOT NULL,
  `folder_format` varchar(255) NOT NULL,
  `file_count` int(10) DEFAULT NULL,
  `note` text NOT NULL,
  `data` text NOT NULL,
  `is_admin` int(10) NOT NULL,
  `inf_name` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `backup_plans`
--

CREATE TABLE `backup_plans` (
  `bpid` int(10) NOT NULL,
  `disabled` tinyint(4) NOT NULL DEFAULT '0',
  `plan_name` varchar(255) NOT NULL,
  `bid` int(10) NOT NULL,
  `frequency` varchar(10) NOT NULL,
  `run_time` varchar(10) NOT NULL,
  `hourly_freq` text,
  `run_day` varchar(10) NOT NULL,
  `run_date` varchar(10) NOT NULL,
  `rotation` int(10) NOT NULL,
  `backup_limit` int(10) NOT NULL DEFAULT '0',
  `restore_limit` int(10) NOT NULL DEFAULT '0',
  `enable_enduser_backup_servers` tinyint(4) DEFAULT '0',
  `nice` tinyint(10) NOT NULL DEFAULT '19',
  `ionice_prio` tinyint(10) NOT NULL DEFAULT '3',
  `ionice_class` tinyint(10) NOT NULL DEFAULT '1',
  `disable_compression` tinyint(4) NOT NULL DEFAULT '0',
  `dir` text NOT NULL,
  `bs_servergroups` text,
  `io_limit` int(10) NOT NULL,
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `backup_servers`
--

CREATE TABLE `backup_servers` (
  `bid` int(10) NOT NULL,
  `type` varchar(10) NOT NULL,
  `name` varchar(255) NOT NULL,
  `hostname` varchar(255) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `ssh_key` int(1) DEFAULT NULL,
  `sshpub_key` text,
  `sshpri_key` text,
  `salt` varchar(20) NOT NULL DEFAULT '',
  `port` int(11) NOT NULL,
  `dir` text NOT NULL,
  `ftps` int(1) DEFAULT '0',
  `internal_hostname` varchar(255) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `bandwidth`
--

CREATE TABLE `bandwidth` (
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `device` varchar(255) NOT NULL DEFAULT '',
  `date` int(10) NOT NULL DEFAULT '0',
  `time` int(10) NOT NULL DEFAULT '0',
  `in` bigint(12) NOT NULL DEFAULT '0',
  `out` bigint(12) NOT NULL DEFAULT '0',
  `c_in` bigint(12) NOT NULL DEFAULT '0',
  `c_out` bigint(12) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `cloud_bandwidth`
--

CREATE TABLE `cloud_bandwidth` (
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `cloud_uid` int(10) NOT NULL DEFAULT '0',
  `cloud_email` varchar(100) NOT NULL DEFAULT '',
  `uid` int(10) NOT NULL DEFAULT '0',
  `user_email` varchar(100) NOT NULL DEFAULT '',
  `bandwidth_used` decimal(12,2) NOT NULL DEFAULT '0.00',
  `date` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `console_sessions`
--

CREATE TABLE `console_sessions` (
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `serid` int(10) NOT NULL DEFAULT '0',
  `start` int(10) NOT NULL DEFAULT '0',
  `duration` int(10) NOT NULL DEFAULT '0',
  `username` varchar(50) NOT NULL DEFAULT '',
  `password` varchar(100) NOT NULL DEFAULT '',
  `port` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='Console Sessions';

-- --------------------------------------------------------

--
-- Table structure for table `disks`
--

CREATE TABLE `disks` (
  `did` int(10) NOT NULL,
  `disk_uuid` varchar(100) NOT NULL DEFAULT '',
  `st_uuid` varchar(100) NOT NULL DEFAULT '',
  `vps_uuid` varchar(100) NOT NULL DEFAULT '',
  `path` varchar(1000) NOT NULL DEFAULT '',
  `primary` tinyint(4) NOT NULL DEFAULT '0',
  `size` decimal(10,3) NOT NULL DEFAULT '0.000',
  `size_unit` varchar(10) NOT NULL DEFAULT '',
  `type` varchar(20) NOT NULL DEFAULT '',
  `format` varchar(100) NOT NULL DEFAULT '',
  `num` int(5) NOT NULL DEFAULT '0',
  `rescue` tinyint(4) NOT NULL DEFAULT '0',
  `extra` text,
  `bus_driver` varchar(100) NOT NULL DEFAULT 'sata',
  `bus_driver_num` int(2) NOT NULL DEFAULT '0',
  `user_uid` int(10) NOT NULL DEFAULT '0',
  `disk_name` text,
  `mnt_point` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `dnsplans`
--

CREATE TABLE `dnsplans` (
  `dnsplid` int(10) NOT NULL,
  `pdnsid` int(10) NOT NULL,
  `plan_name` text,
  `max_domains` int(10) NOT NULL,
  `max_domain_records` int(10) NOT NULL,
  `def_ttl` int(10) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `email_templates`
--

CREATE TABLE `email_templates` (
  `eid` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `mail_type` varchar(6) NOT NULL,
  `is_disable` int(11) NOT NULL,
  `data` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `enduser_backup_servers`
--

CREATE TABLE `enduser_backup_servers` (
  `bserid` int(10) NOT NULL,
  `uid` int(10) NOT NULL,
  `type` varchar(10) NOT NULL,
  `name` varchar(255) NOT NULL,
  `hostname` varchar(255) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(150) NOT NULL,
  `salt` varchar(20) NOT NULL DEFAULT '',
  `port` int(11) NOT NULL,
  `dir` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `enduser_iso`
--

CREATE TABLE `enduser_iso` (
  `isoid` int(5) NOT NULL,
  `uuid` varchar(50) NOT NULL,
  `uid` int(10) NOT NULL,
  `pid` int(10) NOT NULL,
  `iso` text NOT NULL,
  `size` bigint(10) NOT NULL,
  `downloaded` bigint(10) NOT NULL,
  `download_time` int(10) NOT NULL DEFAULT '0',
  `deleted` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `firewall_plans`
--

CREATE TABLE `firewall_plans` (
  `fwid` int(10) NOT NULL,
  `uid` int(100) NOT NULL DEFAULT '0',
  `fw_plan_name` varchar(255) DEFAULT NULL,
  `rules` text,
  `is_admin` int(100) NOT NULL DEFAULT '0',
  `admin_default` int(10) NOT NULL DEFAULT '0',
  `default_policy` int(10) NOT NULL DEFAULT '0',
  `for_servers` tinyint(4) NOT NULL DEFAULT '0',
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `fpass`
--

CREATE TABLE `fpass` (
  `uid` int(10) NOT NULL DEFAULT '0',
  `key` varchar(50) NOT NULL DEFAULT '',
  `time` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `haproxy`
--

CREATE TABLE `haproxy` (
  `id` int(10) NOT NULL,
  `vpsuuid` varchar(16) NOT NULL DEFAULT '',
  `serid` int(10) NOT NULL DEFAULT '0',
  `protocol` varchar(10) NOT NULL DEFAULT '',
  `src_hostname` varchar(255) NOT NULL DEFAULT '',
  `src_port` int(10) NOT NULL DEFAULT '0',
  `dest_ip` varchar(35) NOT NULL DEFAULT '',
  `dest_port` int(10) NOT NULL DEFAULT '0',
  `timeadded` int(10) NOT NULL DEFAULT '0',
  `timeupdated` int(10) NOT NULL DEFAULT '0',
  `skipped` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `invoices`
--

CREATE TABLE `invoices` (
  `invoid` int(10) NOT NULL,
  `invonum` int(5) NOT NULL DEFAULT '0',
  `invodate` int(10) NOT NULL DEFAULT '0',
  `invotime` int(10) NOT NULL DEFAULT '0',
  `duedate` int(10) NOT NULL DEFAULT '0',
  `uid` int(10) NOT NULL DEFAULT '0',
  `paydate` int(10) NOT NULL DEFAULT '0',
  `paytime` int(10) NOT NULL DEFAULT '0',
  `item` text NOT NULL,
  `additional_desc` text,
  `item_desc` text NOT NULL,
  `amt` decimal(10,2) NOT NULL DEFAULT '0.00',
  `disc` decimal(10,2) NOT NULL DEFAULT '0.00',
  `additional_disc` decimal(10,2) NOT NULL DEFAULT '0.00',
  `net` decimal(10,2) NOT NULL DEFAULT '0.00',
  `tax` text,
  `token` varchar(255) NOT NULL DEFAULT '',
  `cancelled` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `ippool`
--

CREATE TABLE `ippool` (
  `ippid` int(10) NOT NULL,
  `ipp_serid` int(10) NOT NULL DEFAULT '0',
  `ippool_name` text,
  `gateway` varchar(50) NOT NULL DEFAULT '',
  `netmask` varchar(50) NOT NULL DEFAULT '',
  `ns1` varchar(50) NOT NULL DEFAULT '',
  `ns2` varchar(50) NOT NULL DEFAULT '',
  `ipv6` tinyint(2) NOT NULL DEFAULT '0',
  `nat` varchar(100) NOT NULL DEFAULT '',
  `nat_name` varchar(100) NOT NULL DEFAULT '',
  `routing` int(11) NOT NULL DEFAULT '0',
  `internal` tinyint(2) NOT NULL DEFAULT '0',
  `bridge` varchar(255) NOT NULL DEFAULT '',
  `mtu` int(10) NOT NULL DEFAULT '0',
  `uid` int(10) NOT NULL DEFAULT '0',
  `vlan` int(11) NOT NULL DEFAULT '0',
  `vlan_tag` int(11) NOT NULL DEFAULT '0',
  `ovs` varchar(100) NOT NULL,
  `ovs_bridge` varchar(100) NOT NULL,
  `pdns_id` int(11) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `ippool_servers`
--

CREATE TABLE `ippool_servers` (
  `ippid` int(10) NOT NULL DEFAULT '0',
  `serid` int(10) NOT NULL DEFAULT '0',
  `sgid` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `ips`
--

CREATE TABLE `ips` (
  `ipid` int(10) NOT NULL,
  `ippid` int(10) NOT NULL DEFAULT '0',
  `ip_serid` int(10) NOT NULL DEFAULT '0',
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `ip` varchar(50) NOT NULL DEFAULT '',
  `ipv6` tinyint(2) NOT NULL DEFAULT '0',
  `ipr_netmask` varchar(20) NOT NULL DEFAULT '',
  `primary` int(5) NOT NULL DEFAULT '0',
  `ipr_ips` text,
  `mac_addr` varchar(20) DEFAULT NULL,
  `locked` int(5) NOT NULL DEFAULT '0',
  `note` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `ips_locked`
--

CREATE TABLE `ips_locked` (
  `ips` text,
  `serid` int(10) DEFAULT '0',
  `time` int(10) DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `ip_logs`
--

CREATE TABLE `ip_logs` (
  `iplid` int(10) NOT NULL,
  `ipid` int(10) NOT NULL DEFAULT '0',
  `ip` varchar(100) NOT NULL DEFAULT '',
  `vpsid` varchar(10) NOT NULL DEFAULT '0',
  `uid` int(10) NOT NULL DEFAULT '0',
  `email` varchar(255) NOT NULL DEFAULT '',
  `cloud_uid` int(10) NOT NULL DEFAULT '0',
  `cloud_email` varchar(255) NOT NULL DEFAULT '',
  `time` int(10) NOT NULL DEFAULT '0',
  `date` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `iso`
--

CREATE TABLE `iso` (
  `uuid` varchar(50) NOT NULL DEFAULT '',
  `iso` text,
  `mg` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `lb_ssl_certs`
--

CREATE TABLE `lb_ssl_certs` (
  `ssl_id` int(11) NOT NULL,
  `ssl_name` varchar(255) DEFAULT NULL,
  `ssl_cert` text,
  `ssl_key` text,
  `ssl_chain` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `load_balancer`
--

CREATE TABLE `load_balancer` (
  `lbid` int(11) NOT NULL,
  `vps_uuid` varchar(50) DEFAULT NULL,
  `uid` int(11) DEFAULT NULL,
  `sgid` int(11) DEFAULT NULL,
  `settings` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `logs_admin`
--

CREATE TABLE `logs_admin` (
  `actid` int(10) NOT NULL,
  `uid` int(10) NOT NULL DEFAULT '0',
  `id` int(10) NOT NULL DEFAULT '0',
  `action` text,
  `data` text,
  `time` int(10) NOT NULL DEFAULT '0',
  `status` int(5) NOT NULL DEFAULT '0',
  `ip` varchar(255) NOT NULL DEFAULT ''
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `logs_login`
--

CREATE TABLE `logs_login` (
  `username` varchar(255) NOT NULL DEFAULT '',
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `time` int(10) NOT NULL DEFAULT '0',
  `status` int(5) NOT NULL DEFAULT '0',
  `ip` varchar(255) NOT NULL DEFAULT ''
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `logs_vps`
--

CREATE TABLE `logs_vps` (
  `actid` int(10) NOT NULL,
  `uid` int(10) NOT NULL DEFAULT '0',
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `action` text,
  `data` text,
  `time` int(10) NOT NULL DEFAULT '0',
  `status` int(5) NOT NULL DEFAULT '0',
  `ip` varchar(255) NOT NULL DEFAULT ''
) ENGINE=MyISAM DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;

-- --------------------------------------------------------

--
-- Table structure for table `media_groups`
--

CREATE TABLE `media_groups` (
  `mgid` int(10) NOT NULL,
  `mg_name` varchar(255) NOT NULL DEFAULT '',
  `mg_desc` text,
  `mg_type` varchar(50) NOT NULL DEFAULT ''
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `notifications`
--

CREATE TABLE `notifications` (
  `nid` int(11) NOT NULL,
  `serid` int(11) NOT NULL DEFAULT '0',
  `action` text NOT NULL,
  `data` text NOT NULL,
  `seen_time` int(11) DEFAULT '0',
  `ins_time` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `os`
--

CREATE TABLE `os` (
  `osid` int(10) NOT NULL DEFAULT '0',
  `osdata` text,
  `mg` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `osreinstall`
--

CREATE TABLE `osreinstall` (
  `osrid` int(10) NOT NULL,
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `osid` int(10) NOT NULL DEFAULT '0',
  `uid` int(10) NOT NULL DEFAULT '0',
  `time` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `os_distros`
--

CREATE TABLE `os_distros` (
  `distro` varchar(50) NOT NULL DEFAULT '' COMMENT 'Small Name',
  `name` varchar(50) NOT NULL DEFAULT '' COMMENT 'Actual Name',
  `desc` text,
  `logo` text,
  `screenshot` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `passthrough`
--

CREATE TABLE `passthrough` (
  `pid` int(10) NOT NULL,
  `dev_name` varchar(255) DEFAULT NULL COMMENT 'PCI device specific',
  `dev_fullname` text NOT NULL COMMENT 'Full info about device',
  `name` varchar(255) NOT NULL,
  `vpsid` int(10) DEFAULT '0',
  `serid` int(10) DEFAULT '0',
  `iommu_grp_num` int(10) DEFAULT '0' COMMENT 'IOMMU group number. Only for PCI devices',
  `iommu_peers_num` int(10) DEFAULT '0' COMMENT 'No. of Iommu group peers',
  `description` text,
  `type` varchar(255) NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT '1'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `pdns`
--

CREATE TABLE `pdns` (
  `id` int(11) NOT NULL,
  `name` varchar(250) NOT NULL,
  `description` text NOT NULL,
  `sql_ipaddress` varchar(200) NOT NULL,
  `sql_port` int(11) NOT NULL DEFAULT '3306',
  `sql_username` varchar(200) NOT NULL,
  `sql_password` varchar(250) NOT NULL,
  `sql_database` varchar(200) NOT NULL,
  `use_ssl` int(5) NOT NULL DEFAULT '0',
  `encrypt_sql_pass` int(10) NOT NULL DEFAULT '0',
  `salt` varchar(20) NOT NULL DEFAULT ''
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `plans`
--

CREATE TABLE `plans` (
  `plid` int(10) NOT NULL,
  `plan_name` text,
  `virt` varchar(50) NOT NULL DEFAULT '',
  `ips` int(10) NOT NULL DEFAULT '0',
  `ips6` int(10) NOT NULL DEFAULT '0',
  `ips6_subnet` int(10) NOT NULL DEFAULT '0',
  `ips_int` int(10) NOT NULL DEFAULT '0',
  `space` float(10,3) DEFAULT NULL,
  `inodes` int(10) NOT NULL DEFAULT '0',
  `ram` int(10) NOT NULL DEFAULT '0',
  `burst` int(10) NOT NULL DEFAULT '0',
  `swap` int(10) NOT NULL DEFAULT '0',
  `cpu` int(10) NOT NULL DEFAULT '0',
  `cores` int(10) NOT NULL DEFAULT '0',
  `cpu_percent` decimal(10,2) NOT NULL DEFAULT '0.00',
  `bandwidth` int(10) NOT NULL DEFAULT '0',
  `network_speed` int(10) NOT NULL DEFAULT '0',
  `upload_speed` int(10) NOT NULL DEFAULT '0',
  `nic_type` varchar(20) NOT NULL DEFAULT '',
  `io` int(10) NOT NULL DEFAULT '0',
  `virtio` int(10) NOT NULL DEFAULT '0',
  `ubc` text,
  `ploop` int(2) NOT NULL DEFAULT '0',
  `band_suspend` int(5) NOT NULL DEFAULT '0',
  `dns_nameserver` text,
  `ppp` int(10) NOT NULL DEFAULT '0',
  `tuntap` int(10) NOT NULL DEFAULT '0',
  `control_panel` text NOT NULL,
  `mgs` text,
  `cpu_mode` varchar(255) DEFAULT NULL,
  `sec_iso` text,
  `hvm` int(5) NOT NULL DEFAULT '0',
  `kvm_cache` varchar(20) NOT NULL,
  `io_mode` varchar(20) NOT NULL,
  `osreinstall_limit` int(10) NOT NULL DEFAULT '0',
  `total_iops_sec` bigint(20) NOT NULL DEFAULT '0',
  `read_bytes_sec` bigint(20) NOT NULL DEFAULT '0',
  `write_bytes_sec` bigint(20) NOT NULL DEFAULT '0',
  `vnc_keymap` varchar(20) NOT NULL,
  `osid` int(10) NOT NULL DEFAULT '0',
  `kvm_vga` int(4) NOT NULL DEFAULT '0',
  `acceleration` int(4) NOT NULL DEFAULT '0',
  `vif_type` varchar(100) NOT NULL,
  `pv_on_hvm` int(4) NOT NULL DEFAULT '0',
  `iso` text,
  `vnc` int(4) NOT NULL DEFAULT '0',
  `admin_managed` int(5) NOT NULL DEFAULT '0',
  `shadow` int(10) NOT NULL DEFAULT '0',
  `acpi` int(10) NOT NULL DEFAULT '0',
  `apic` int(10) NOT NULL DEFAULT '0',
  `pae` int(10) NOT NULL DEFAULT '0',
  `recipe` text,
  `topology_sockets` int(5) NOT NULL DEFAULT '0',
  `topology_cores` int(5) NOT NULL DEFAULT '0',
  `topology_threads` int(5) NOT NULL DEFAULT '0',
  `disable_nw_config` int(5) NOT NULL DEFAULT '0',
  `rdp` int(5) NOT NULL DEFAULT '0',
  `openvz_features` text,
  `speed_cap` text,
  `numa` int(5) NOT NULL DEFAULT '0',
  `bpid` int(10) NOT NULL DEFAULT '0',
  `install_xentools` int(5) NOT NULL DEFAULT '0',
  `ippoolid` text,
  `is_enabled` tinyint(4) NOT NULL DEFAULT '1',
  `bus_driver` varchar(100) NOT NULL,
  `bus_driver_num` int(2) NOT NULL,
  `webuzo_data` text,
  `load_balancer` varchar(50) NOT NULL DEFAULT '0',
  `fwid` int(10) NOT NULL DEFAULT '0',
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `pricing`
--

CREATE TABLE `pricing` (
  `prid` int(10) NOT NULL,
  `plid` int(10) NOT NULL,
  `sgid` int(10) NOT NULL,
  `h_rate` decimal(10,3) NOT NULL,
  `m_rate` decimal(10,3) NOT NULL,
  `y_rate` decimal(10,3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `recipes`
--

CREATE TABLE `recipes` (
  `rid` int(10) NOT NULL,
  `name` varchar(255) NOT NULL DEFAULT '',
  `code` text,
  `desc` text,
  `logo` text,
  `shell` varchar(255) NOT NULL DEFAULT '#!/bin/sh',
  `status` int(11) NOT NULL DEFAULT '0',
  `admin_only` int(2) NOT NULL DEFAULT '0',
  `uid` int(10) NOT NULL DEFAULT '0',
  `type` varchar(10) NOT NULL,
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `registry`
--

CREATE TABLE `registry` (
  `name` varchar(255) NOT NULL,
  `value` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `self_shutdown`
--

CREATE TABLE `self_shutdown` (
  `id` int(11) NOT NULL,
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `time` int(10) NOT NULL DEFAULT '0',
  `action` int(1) DEFAULT NULL COMMENT 'Action start = 0, stop = 1, restart = 2, poweroff = 3;',
  `status` int(1) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `servers`
--

CREATE TABLE `servers` (
  `serid` int(10) NOT NULL,
  `sgid` int(10) NOT NULL DEFAULT '0',
  `server_name` text,
  `virt` varchar(50) NOT NULL DEFAULT '',
  `ip` varchar(50) NOT NULL DEFAULT '',
  `internal_ip` varchar(50) NOT NULL DEFAULT '',
  `vnc_ip` varchar(50) NOT NULL DEFAULT '',
  `key` varchar(64) NOT NULL DEFAULT '',
  `pass` varchar(64) NOT NULL DEFAULT '',
  `settings` text,
  `unique_txt` varchar(255) NOT NULL DEFAULT '',
  `lv` varchar(255) NOT NULL DEFAULT '',
  `hvm` int(5) NOT NULL DEFAULT '0',
  `licnumvs` int(10) NOT NULL DEFAULT '-1',
  `total_ram` int(10) NOT NULL DEFAULT '0',
  `overcommit` int(10) NOT NULL DEFAULT '0',
  `ram` int(10) NOT NULL DEFAULT '0',
  `total_space` int(10) NOT NULL DEFAULT '0',
  `space` int(10) NOT NULL DEFAULT '0',
  `os` varchar(255) DEFAULT '',
  `os_arch` varchar(100) DEFAULT '',
  `uname` varchar(255) DEFAULT '',
  `version` varchar(10) DEFAULT '',
  `patch` int(5) NOT NULL DEFAULT '0',
  `lic_expires` text,
  `checked` int(10) NOT NULL DEFAULT '0',
  `locked` text,
  `vcores` int(10) NOT NULL DEFAULT '0',
  `ips` int(10) NOT NULL DEFAULT '0',
  `ipv6` int(10) NOT NULL DEFAULT '0',
  `ipv6_subnet` int(10) NOT NULL DEFAULT '0',
  `ips_int` int(10) NOT NULL DEFAULT '0',
  `bandwidth` bigint(12) NOT NULL DEFAULT '0',
  `update_resource` tinyint(2) NOT NULL DEFAULT '0',
  `location` varchar(255) DEFAULT '',
  `status` tinyint(1) NOT NULL DEFAULT '1',
  `last_reverse_sync` int(10) NOT NULL DEFAULT '0',
  `ha_master` int(10) NOT NULL DEFAULT '0',
  `sys_load` float(6,2) NOT NULL DEFAULT '0.00',
  `fwid` int(10) NOT NULL DEFAULT '0',
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `server_groups`
--

CREATE TABLE `server_groups` (
  `sgid` int(10) NOT NULL,
  `sg_name` varchar(255) NOT NULL DEFAULT '',
  `sg_reseller_name` varchar(255) NOT NULL DEFAULT '',
  `sg_desc` text,
  `sg_select` int(10) NOT NULL DEFAULT '0',
  `sg_ha` int(10) NOT NULL DEFAULT '0',
  `sg_key_type` varchar(50) DEFAULT NULL,
  `sg_public_key` text,
  `sg_private_key` text,
  `sg_password` varchar(50) NOT NULL,
  `sg_salt` varchar(20) NOT NULL DEFAULT '',
  `sg_data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `server_sshkeys`
--

CREATE TABLE `server_sshkeys` (
  `serid` int(10) NOT NULL DEFAULT '0',
  `type` varchar(50) NOT NULL DEFAULT '',
  `time` int(10) NOT NULL DEFAULT '0',
  `public_key` text,
  `private_key` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='Server SSH Keys';

-- --------------------------------------------------------

--
-- Table structure for table `sessions`
--

CREATE TABLE `sessions` (
  `sid` varchar(32) NOT NULL DEFAULT '',
  `last_updated` int(10) NOT NULL DEFAULT '0',
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `smartctl_devices`
--

CREATE TABLE `smartctl_devices` (
  `id` int(11) NOT NULL,
  `serid` smallint(10) DEFAULT NULL,
  `time` int(15) DEFAULT NULL,
  `devices` varchar(30) DEFAULT NULL,
  `model_name` text,
  `serial_number` text,
  `firmware_version` text,
  `logical_block_size` tinyint(5) DEFAULT NULL,
  `rotation` int(5) DEFAULT NULL,
  `temperature` varchar(10) DEFAULT NULL,
  `sata_version` varchar(15) DEFAULT NULL,
  `size` varchar(10) DEFAULT NULL,
  `health` int(1) DEFAULT NULL,
  `disk_type` varchar(5) NOT NULL,
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `ssh_keys`
--

CREATE TABLE `ssh_keys` (
  `keyid` int(10) NOT NULL,
  `uuid` varchar(50) NOT NULL,
  `uid` int(10) NOT NULL,
  `name` varchar(255) NOT NULL,
  `value` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `status`
--

CREATE TABLE `status` (
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `time` int(10) NOT NULL DEFAULT '0',
  `status` int(10) NOT NULL DEFAULT '0',
  `disk` bigint(12) NOT NULL DEFAULT '0',
  `inode` bigint(12) NOT NULL DEFAULT '0',
  `ram` bigint(12) NOT NULL DEFAULT '0',
  `cpu` float(5,2) NOT NULL DEFAULT '0.00',
  `actual_cpu` float(5,2) NOT NULL DEFAULT '0.00',
  `net_in` bigint(12) NOT NULL DEFAULT '0',
  `net_out` bigint(12) NOT NULL DEFAULT '0',
  `io_read` int(10) NOT NULL DEFAULT '0',
  `io_write` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `storage`
--

CREATE TABLE `storage` (
  `stid` int(10) NOT NULL,
  `st_uuid` varchar(50) NOT NULL DEFAULT '',
  `name` varchar(255) NOT NULL DEFAULT '',
  `path` varchar(255) NOT NULL DEFAULT '',
  `type` varchar(50) NOT NULL DEFAULT '',
  `format` varchar(50) NOT NULL DEFAULT '',
  `size` decimal(10,2) NOT NULL DEFAULT '0.00',
  `free` decimal(10,2) NOT NULL DEFAULT '0.00',
  `oversell` int(10) NOT NULL DEFAULT '0',
  `alert_threshold` decimal(10,2) NOT NULL DEFAULT '0.00',
  `primary_storage` int(5) NOT NULL DEFAULT '0',
  `project_name` text,
  `last_alert` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `storage_servers`
--

CREATE TABLE `storage_servers` (
  `stid` int(10) NOT NULL DEFAULT '0',
  `serid` int(10) NOT NULL DEFAULT '0',
  `sgid` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `system_alerts`
--

CREATE TABLE `system_alerts` (
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `time` int(10) NOT NULL DEFAULT '0',
  `cpu` decimal(8,2) NOT NULL DEFAULT '0.00',
  `ram` decimal(8,2) NOT NULL DEFAULT '0.00',
  `disk` decimal(8,2) NOT NULL DEFAULT '0.00'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `tasks`
--

CREATE TABLE `tasks` (
  `actid` int(10) NOT NULL,
  `slaveactid` int(10) DEFAULT '0',
  `uid` int(10) NOT NULL DEFAULT '0',
  `vpsid` int(10) NOT NULL DEFAULT '0',
  `serid` int(10) NOT NULL DEFAULT '0',
  `action` text,
  `data` text,
  `time` int(10) NOT NULL DEFAULT '0',
  `status_txt` text,
  `status` int(5) NOT NULL DEFAULT '0',
  `progress` varchar(255) DEFAULT NULL,
  `started` int(10) NOT NULL DEFAULT '0',
  `updated` int(10) NOT NULL DEFAULT '0',
  `ended` int(10) NOT NULL DEFAULT '0',
  `proc_id` int(10) NOT NULL DEFAULT '0',
  `ip` varchar(255) NOT NULL DEFAULT '',
  `internal` int(5) NOT NULL DEFAULT '0',
  `logs` mediumblob
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `tax_rules`
--

CREATE TABLE `tax_rules` (
  `id` int(10) NOT NULL,
  `level` int(1) NOT NULL DEFAULT '0',
  `name` text,
  `state` text,
  `country` text,
  `taxrate` decimal(10,2) NOT NULL DEFAULT '0.00',
  `default_rule` int(11) NOT NULL DEFAULT '0',
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `tmp_transactions`
--

CREATE TABLE `tmp_transactions` (
  `id` bigint(20) NOT NULL,
  `token` varchar(50) NOT NULL,
  `gateway` varchar(50) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `fees` decimal(10,2) NOT NULL DEFAULT '0.00',
  `currency` varchar(10) NOT NULL,
  `is_paid` tinyint(4) NOT NULL,
  `uid` int(10) NOT NULL,
  `date_created` int(10) NOT NULL,
  `date_completed` int(10) NOT NULL,
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `to_master`
--

CREATE TABLE `to_master` (
  `tables` varchar(100) NOT NULL DEFAULT '',
  `columns` varchar(100) NOT NULL DEFAULT '',
  `id` varchar(32) NOT NULL DEFAULT '0',
  `unique_column` varchar(100) NOT NULL DEFAULT '',
  `value` mediumtext
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `transactions`
--

CREATE TABLE `transactions` (
  `trid` int(12) NOT NULL,
  `uid` int(10) NOT NULL DEFAULT '0',
  `date` int(10) NOT NULL DEFAULT '0',
  `unixtime` int(10) NOT NULL DEFAULT '0',
  `invoid` int(10) NOT NULL DEFAULT '0',
  `gateway` varchar(200) NOT NULL DEFAULT '' COMMENT 'The Gateway name in text',
  `token` varchar(100) NOT NULL DEFAULT '',
  `amt` decimal(10,2) NOT NULL DEFAULT '0.00',
  `fees` decimal(10,2) NOT NULL DEFAULT '0.00',
  `net` decimal(10,2) NOT NULL DEFAULT '0.00',
  `bal` decimal(10,2) NOT NULL DEFAULT '0.00' COMMENT 'Remaining balance after this transaction',
  `used` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'If set to 1 then we can skip in calculating balance'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `usage`
--

CREATE TABLE `usage` (
  `usid` int(10) NOT NULL,
  `vps_uuid` varchar(100) NOT NULL DEFAULT '0',
  `uid` int(10) NOT NULL DEFAULT '0' COMMENT 'User ID',
  `serid` int(10) NOT NULL DEFAULT '0' COMMENT 'The Server ID so that we can update the SGID',
  `sgid` int(10) NOT NULL DEFAULT '0' COMMENT 'Server Group of this VPS',
  `plid` int(10) NOT NULL DEFAULT '0' COMMENT 'The VPS Plan ID',
  `invoid` int(10) NOT NULL DEFAULT '0' COMMENT 'The invoice to which this usage is linked',
  `resource` varchar(100) DEFAULT '' COMMENT 'Blank is for the VPS itself',
  `resource_val` decimal(10,3) NOT NULL DEFAULT '0.000' COMMENT 'If its a resouce the value to calculate usage',
  `starttime` int(10) NOT NULL DEFAULT '0',
  `endtime` int(10) NOT NULL DEFAULT '0',
  `updatetime` int(10) NOT NULL DEFAULT '0',
  `h_used` decimal(10,2) NOT NULL DEFAULT '0.00' COMMENT 'The estimated amount that will be charged for the VPS',
  `data` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `uid` int(10) NOT NULL,
  `password` varchar(50) NOT NULL DEFAULT '',
  `email` varchar(255) NOT NULL DEFAULT '',
  `type` int(10) NOT NULL DEFAULT '0',
  `aclid` int(10) NOT NULL DEFAULT '0',
  `pid` int(10) NOT NULL DEFAULT '0',
  `uplid` int(10) NOT NULL DEFAULT '0' COMMENT 'User Plan ID',
  `inhouse_billing` tinyint(2) NOT NULL DEFAULT '0',
  `cur_bal` decimal(10,2) NOT NULL DEFAULT '0.00' COMMENT 'The current balance deposited by the user',
  `cur_usage` decimal(10,2) NOT NULL DEFAULT '0.00' COMMENT 'The current usage of all VPS and resources',
  `cur_invoices` decimal(10,2) NOT NULL DEFAULT '0.00' COMMENT 'The outstanding invoices total',
  `max_cost` int(10) NOT NULL DEFAULT '0',
  `num_vs` int(10) NOT NULL DEFAULT '0',
  `num_users` int(10) NOT NULL DEFAULT '0',
  `space` int(10) NOT NULL DEFAULT '0',
  `ram` int(10) NOT NULL DEFAULT '0',
  `burst` int(10) NOT NULL DEFAULT '0',
  `bandwidth` int(10) NOT NULL DEFAULT '0',
  `cpu` int(10) NOT NULL DEFAULT '0',
  `cores` int(10) NOT NULL DEFAULT '0',
  `cpu_percent` int(10) NOT NULL DEFAULT '0',
  `num_cores` int(10) NOT NULL DEFAULT '0',
  `num_ipv4` int(10) NOT NULL DEFAULT '0',
  `num_ip_int` int(10) NOT NULL DEFAULT '0',
  `num_ipv6` int(10) NOT NULL DEFAULT '0',
  `num_ipv6_subnet` int(10) NOT NULL DEFAULT '0',
  `allowed_virts` varchar(255) NOT NULL DEFAULT '',
  `network_speed` int(10) NOT NULL DEFAULT '0',
  `upload_speed` int(10) NOT NULL DEFAULT '0',
  `openvz` tinyint(2) NOT NULL DEFAULT '0',
  `xen` tinyint(2) NOT NULL DEFAULT '0',
  `xenhvm` tinyint(2) NOT NULL DEFAULT '0',
  `kvm` tinyint(2) NOT NULL DEFAULT '0',
  `sg` text,
  `mg` text,
  `preferences` text,
  `dnsplid` int(10) NOT NULL,
  `act_status` tinyint(2) NOT NULL DEFAULT '1',
  `activation_code` varchar(100) NOT NULL DEFAULT '',
  `date_created` int(10) NOT NULL DEFAULT '0',
  `service_period` int(5) NOT NULL DEFAULT '0',
  `band_suspend` int(5) NOT NULL DEFAULT '0',
  `billing_warn` text COMMENT 'Serialized Array of data related to billing issues',
  `suspended` text,
  `foreign_uid` int(10) DEFAULT '0' COMMENT 'It will be the uid of the users billing system',
  `webuzo_prem_apps` tinyint(4) NOT NULL DEFAULT '0',
  `space_per_vm` int(10) NOT NULL DEFAULT '0',
  `total_iops_sec` bigint(20) NOT NULL DEFAULT '0',
  `read_bytes_sec` bigint(20) NOT NULL DEFAULT '0',
  `write_bytes_sec` bigint(20) NOT NULL DEFAULT '0',
  `kyc_status` int(10) NOT NULL DEFAULT '0' COMMENT '-1=pending, 0=not done, 1=approved, 2=rejected',
  `kyc_details` text,
  `kyc_last_done` int(10) NOT NULL DEFAULT '0',
  `kyc_settings` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `user_meta`
--

CREATE TABLE `user_meta` (
  `umeta_id` bigint(20) UNSIGNED NOT NULL,
  `uid` bigint(20) UNSIGNED NOT NULL DEFAULT '0',
  `meta_key` varchar(255) DEFAULT NULL,
  `meta_value` longtext
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `user_plans`
--

CREATE TABLE `user_plans` (
  `uplid` int(10) NOT NULL,
  `plan_name` varchar(255) NOT NULL DEFAULT '',
  `type` int(10) NOT NULL DEFAULT '0' COMMENT 'User Account type',
  `aclid` int(10) NOT NULL DEFAULT '0',
  `inhouse_billing` tinyint(2) NOT NULL DEFAULT '0' COMMENT 'Are we billing or not',
  `max_cost` int(10) NOT NULL DEFAULT '0' COMMENT 'Max Cost per VM',
  `num_vs` int(10) NOT NULL DEFAULT '0',
  `num_users` int(10) NOT NULL DEFAULT '0',
  `space` int(10) NOT NULL DEFAULT '0',
  `ram` int(10) NOT NULL DEFAULT '0',
  `burst` int(10) NOT NULL DEFAULT '0',
  `bandwidth` int(10) NOT NULL DEFAULT '0',
  `cpu` int(10) NOT NULL DEFAULT '0',
  `cores` int(10) NOT NULL DEFAULT '0',
  `cpu_percent` int(10) NOT NULL DEFAULT '0',
  `num_cores` int(10) NOT NULL DEFAULT '0',
  `num_ipv4` int(10) NOT NULL DEFAULT '0',
  `num_ip_int` int(10) NOT NULL DEFAULT '0',
  `num_ipv6` int(10) NOT NULL DEFAULT '0',
  `num_ipv6_subnet` int(10) NOT NULL DEFAULT '0',
  `allowed_virts` varchar(255) NOT NULL DEFAULT '',
  `network_speed` int(10) NOT NULL DEFAULT '0',
  `upload_speed` int(10) NOT NULL DEFAULT '0',
  `sg` text,
  `mg` text,
  `dnsplid` int(10) NOT NULL,
  `service_period` int(5) NOT NULL DEFAULT '0',
  `band_suspend` int(5) NOT NULL DEFAULT '0',
  `date_created` int(10) NOT NULL DEFAULT '0',
  `space_per_vm` int(10) NOT NULL DEFAULT '0',
  `total_iops_sec` bigint(20) NOT NULL DEFAULT '0',
  `read_bytes_sec` bigint(20) NOT NULL DEFAULT '0',
  `write_bytes_sec` bigint(20) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `vps`
--

CREATE TABLE `vps` (
  `vpsid` int(10) NOT NULL,
  `vps_name` text,
  `uuid` varchar(50) NOT NULL DEFAULT '',
  `serid` int(10) NOT NULL DEFAULT '0',
  `time` int(10) NOT NULL DEFAULT '0',
  `edittime` int(10) NOT NULL DEFAULT '0',
  `virt` varchar(32) NOT NULL,
  `uid` int(10) NOT NULL DEFAULT '0',
  `plid` int(10) NOT NULL DEFAULT '0',
  `hostname` text,
  `osid` int(10) NOT NULL DEFAULT '0',
  `os_name` varchar(255) NOT NULL DEFAULT '',
  `iso` text,
  `sec_iso` text,
  `boot` text,
  `space` int(10) NOT NULL DEFAULT '0',
  `inodes` int(10) NOT NULL DEFAULT '0',
  `ram` int(10) NOT NULL DEFAULT '0',
  `burst` int(10) NOT NULL DEFAULT '0',
  `swap` int(10) NOT NULL DEFAULT '0',
  `cpu` int(10) NOT NULL DEFAULT '0',
  `cores` int(10) NOT NULL DEFAULT '0',
  `cpupin` varchar(150) NOT NULL DEFAULT '-1',
  `cpu_percent` decimal(10,2) NOT NULL DEFAULT '0.00',
  `bandwidth` int(10) NOT NULL DEFAULT '0',
  `network_speed` int(10) NOT NULL DEFAULT '0',
  `upload_speed` int(10) NOT NULL DEFAULT '0',
  `io` int(10) NOT NULL DEFAULT '0',
  `ubc` text,
  `acpi` int(5) NOT NULL DEFAULT '0',
  `apic` int(5) NOT NULL DEFAULT '0',
  `pae` int(5) NOT NULL DEFAULT '0',
  `shadow` int(5) NOT NULL DEFAULT '0',
  `vnc` int(5) NOT NULL DEFAULT '0',
  `vncport` int(10) NOT NULL DEFAULT '0',
  `vnc_passwd` varchar(50) NOT NULL DEFAULT '',
  `hvm` int(5) NOT NULL DEFAULT '0',
  `suspended` int(5) NOT NULL DEFAULT '0',
  `suspend_reason` text,
  `nw_suspended` text,
  `rescue` int(10) NOT NULL DEFAULT '0',
  `band_suspend` int(5) NOT NULL DEFAULT '0',
  `tuntap` int(10) NOT NULL DEFAULT '0',
  `ppp` int(10) NOT NULL DEFAULT '0',
  `ploop` int(10) NOT NULL DEFAULT '0',
  `dns_nameserver` text,
  `osreinstall_limit` int(10) NOT NULL DEFAULT '0',
  `preferences` text,
  `nic_type` varchar(20) NOT NULL,
  `vif_type` varchar(10) DEFAULT NULL,
  `virtio` tinyint(1) DEFAULT NULL,
  `pv_on_hvm` tinyint(4) NOT NULL DEFAULT '0',
  `disks` text,
  `kvm_cache` varchar(20) NOT NULL DEFAULT '',
  `io_mode` varchar(20) NOT NULL DEFAULT '',
  `cpu_mode` varchar(255) NOT NULL DEFAULT '',
  `total_iops_sec` bigint(20) NOT NULL DEFAULT '0',
  `read_bytes_sec` bigint(20) NOT NULL DEFAULT '0',
  `write_bytes_sec` bigint(20) NOT NULL DEFAULT '0',
  `kvm_vga` int(5) NOT NULL DEFAULT '0',
  `acceleration` int(5) NOT NULL DEFAULT '0',
  `vnc_keymap` varchar(20) NOT NULL DEFAULT '',
  `routing` tinyint(1) NOT NULL,
  `mg` text,
  `used_bandwidth` decimal(12,2) NOT NULL DEFAULT '0.00',
  `cached_disk` text,
  `webuzo` int(10) NOT NULL DEFAULT '0',
  `disable_ebtables` int(5) NOT NULL DEFAULT '0',
  `install_xentools` int(5) NOT NULL DEFAULT '0',
  `admin_managed` int(5) NOT NULL DEFAULT '0',
  `rdp` int(10) NOT NULL DEFAULT '0',
  `topology_sockets` int(5) NOT NULL DEFAULT '0',
  `topology_cores` int(5) NOT NULL DEFAULT '0',
  `topology_threads` int(5) NOT NULL DEFAULT '0',
  `mac` varchar(20) NOT NULL DEFAULT '',
  `notes` text,
  `disable_nw_config` int(5) NOT NULL DEFAULT '0',
  `locked` text,
  `openvz_features` text,
  `speed_cap` text,
  `numa` int(5) NOT NULL DEFAULT '0',
  `bpid` int(10) NOT NULL DEFAULT '0',
  `bserid` int(10) NOT NULL DEFAULT '0',
  `timezone` varchar(50) DEFAULT NULL,
  `ha` int(2) NOT NULL DEFAULT '0',
  `load_balancer` varchar(50) NOT NULL DEFAULT '0',
  `data` text,
  `fwid` int(10) NOT NULL DEFAULT '0',
  `admin_fwid` int(10) NOT NULL DEFAULT '0',
  `current_resource` text,
  `plan_expiry` int(11) NOT NULL DEFAULT '0',
  `machine_status` int(10) NOT NULL DEFAULT '0',
  `tags` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `vpsbackup_settings`
--

CREATE TABLE `vpsbackup_settings` (
  `vbid` int(10) NOT NULL,
  `serid` int(10) NOT NULL DEFAULT '0',
  `bid` int(10) NOT NULL,
  `enabled` tinyint(4) NOT NULL DEFAULT '0',
  `newvps` tinyint(4) NOT NULL DEFAULT '0',
  `frequency` varchar(10) NOT NULL,
  `run_time` varchar(10) NOT NULL,
  `hourly_freq` text,
  `run_day` varchar(10) NOT NULL,
  `run_date` varchar(10) NOT NULL,
  `rotation` int(10) NOT NULL,
  `vpsids` text NOT NULL,
  `nice` tinyint(10) NOT NULL DEFAULT '19',
  `ionice_prio` tinyint(10) NOT NULL DEFAULT '3',
  `ionice_class` tinyint(10) NOT NULL DEFAULT '1',
  `disable_compression` tinyint(4) NOT NULL DEFAULT '0',
  `dir` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `vps_meta`
--

CREATE TABLE `vps_meta` (
  `vmeta_id` bigint(20) UNSIGNED NOT NULL,
  `serid` int(10) DEFAULT '0',
  `vps_uuid` varchar(50) NOT NULL,
  `meta_key` varchar(255) DEFAULT NULL,
  `meta_value` longtext
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `vps_name`
--

CREATE TABLE `vps_name` (
  `vpsname` text NOT NULL,
  `virt` varchar(32) NOT NULL,
  `serid` int(10) DEFAULT '0',
  `time` int(10) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admin_acl`
--
ALTER TABLE `admin_acl`
  ADD PRIMARY KEY (`aclid`);

--
-- Indexes for table `admin_notes`
--
ALTER TABLE `admin_notes`
  ADD PRIMARY KEY (`noteid`);

--
-- Indexes for table `api`
--
ALTER TABLE `api`
  ADD PRIMARY KEY (`idapi`),
  ADD UNIQUE KEY `apikey` (`apikey`);

--
-- Indexes for table `api_log`
--
ALTER TABLE `api_log`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `backups`
--
ALTER TABLE `backups`
  ADD PRIMARY KEY (`bkid`);

--
-- Indexes for table `backup_plans`
--
ALTER TABLE `backup_plans`
  ADD PRIMARY KEY (`bpid`);

--
-- Indexes for table `backup_servers`
--
ALTER TABLE `backup_servers`
  ADD PRIMARY KEY (`bid`);

--
-- Indexes for table `bandwidth`
--
ALTER TABLE `bandwidth`
  ADD UNIQUE KEY `vpsid` (`vpsid`,`device`,`date`,`time`);

--
-- Indexes for table `console_sessions`
--
ALTER TABLE `console_sessions`
  ADD UNIQUE KEY `vpsid` (`vpsid`);

--
-- Indexes for table `disks`
--
ALTER TABLE `disks`
  ADD PRIMARY KEY (`did`),
  ADD UNIQUE KEY `disk_uuid` (`disk_uuid`);

--
-- Indexes for table `dnsplans`
--
ALTER TABLE `dnsplans`
  ADD PRIMARY KEY (`dnsplid`);

--
-- Indexes for table `email_templates`
--
ALTER TABLE `email_templates`
  ADD PRIMARY KEY (`eid`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `enduser_backup_servers`
--
ALTER TABLE `enduser_backup_servers`
  ADD PRIMARY KEY (`bserid`);

--
-- Indexes for table `enduser_iso`
--
ALTER TABLE `enduser_iso`
  ADD PRIMARY KEY (`isoid`),
  ADD UNIQUE KEY `uuid` (`uuid`);

--
-- Indexes for table `firewall_plans`
--
ALTER TABLE `firewall_plans`
  ADD PRIMARY KEY (`fwid`);

--
-- Indexes for table `haproxy`
--
ALTER TABLE `haproxy`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `serid` (`serid`,`src_hostname`,`src_port`);

--
-- Indexes for table `invoices`
--
ALTER TABLE `invoices`
  ADD PRIMARY KEY (`invoid`);

--
-- Indexes for table `ippool`
--
ALTER TABLE `ippool`
  ADD PRIMARY KEY (`ippid`);

--
-- Indexes for table `ips`
--
ALTER TABLE `ips`
  ADD PRIMARY KEY (`ipid`),
  ADD KEY `vpsid` (`vpsid`),
  ADD KEY `ippid_index` (`ippid`);

--
-- Indexes for table `ip_logs`
--
ALTER TABLE `ip_logs`
  ADD PRIMARY KEY (`iplid`);

--
-- Indexes for table `lb_ssl_certs`
--
ALTER TABLE `lb_ssl_certs`
  ADD PRIMARY KEY (`ssl_id`);

--
-- Indexes for table `load_balancer`
--
ALTER TABLE `load_balancer`
  ADD PRIMARY KEY (`lbid`);

--
-- Indexes for table `logs_admin`
--
ALTER TABLE `logs_admin`
  ADD PRIMARY KEY (`actid`);

--
-- Indexes for table `logs_vps`
--
ALTER TABLE `logs_vps`
  ADD PRIMARY KEY (`actid`);

--
-- Indexes for table `media_groups`
--
ALTER TABLE `media_groups`
  ADD PRIMARY KEY (`mgid`);

--
-- Indexes for table `notifications`
--
ALTER TABLE `notifications`
  ADD PRIMARY KEY (`nid`);

--
-- Indexes for table `os`
--
ALTER TABLE `os`
  ADD UNIQUE KEY `osid` (`osid`);

--
-- Indexes for table `osreinstall`
--
ALTER TABLE `osreinstall`
  ADD PRIMARY KEY (`osrid`);

--
-- Indexes for table `os_distros`
--
ALTER TABLE `os_distros`
  ADD UNIQUE KEY `distro` (`distro`);

--
-- Indexes for table `passthrough`
--
ALTER TABLE `passthrough`
  ADD PRIMARY KEY (`pid`);

--
-- Indexes for table `pdns`
--
ALTER TABLE `pdns`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `plans`
--
ALTER TABLE `plans`
  ADD PRIMARY KEY (`plid`);

--
-- Indexes for table `pricing`
--
ALTER TABLE `pricing`
  ADD PRIMARY KEY (`prid`),
  ADD UNIQUE KEY `pp_unique_plid_sgid` (`plid`,`sgid`);

--
-- Indexes for table `recipes`
--
ALTER TABLE `recipes`
  ADD PRIMARY KEY (`rid`);

--
-- Indexes for table `registry`
--
ALTER TABLE `registry`
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `self_shutdown`
--
ALTER TABLE `self_shutdown`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `servers`
--
ALTER TABLE `servers`
  ADD PRIMARY KEY (`serid`);

--
-- Indexes for table `server_groups`
--
ALTER TABLE `server_groups`
  ADD PRIMARY KEY (`sgid`);

--
-- Indexes for table `server_sshkeys`
--
ALTER TABLE `server_sshkeys`
  ADD UNIQUE KEY `serid` (`serid`);

--
-- Indexes for table `sessions`
--
ALTER TABLE `sessions`
  ADD PRIMARY KEY (`sid`);

--
-- Indexes for table `smartctl_devices`
--
ALTER TABLE `smartctl_devices`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `ssh_keys`
--
ALTER TABLE `ssh_keys`
  ADD PRIMARY KEY (`keyid`),
  ADD UNIQUE KEY `uuid` (`uuid`);

--
-- Indexes for table `storage`
--
ALTER TABLE `storage`
  ADD PRIMARY KEY (`stid`);

--
-- Indexes for table `storage_servers`
--
ALTER TABLE `storage_servers`
  ADD UNIQUE KEY `stid` (`stid`,`serid`,`sgid`);

--
-- Indexes for table `tasks`
--
ALTER TABLE `tasks`
  ADD PRIMARY KEY (`actid`);

--
-- Indexes for table `tax_rules`
--
ALTER TABLE `tax_rules`
  ADD PRIMARY KEY (`id`),
  ADD KEY `state_country` (`state`(32),`country`(2));

--
-- Indexes for table `tmp_transactions`
--
ALTER TABLE `tmp_transactions`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `to_master`
--
ALTER TABLE `to_master`
  ADD UNIQUE KEY `tables` (`tables`,`columns`,`id`);

--
-- Indexes for table `transactions`
--
ALTER TABLE `transactions`
  ADD PRIMARY KEY (`trid`),
  ADD KEY `uid` (`uid`,`amt`,`net`),
  ADD KEY `used` (`used`);

--
-- Indexes for table `usage`
--
ALTER TABLE `usage`
  ADD PRIMARY KEY (`usid`),
  ADD KEY `vps_uuid` (`vps_uuid`),
  ADD KEY `endtime` (`endtime`),
  ADD KEY `invoid` (`invoid`),
  ADD KEY `resource` (`resource`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`uid`),
  ADD KEY `email` (`email`);

--
-- Indexes for table `user_meta`
--
ALTER TABLE `user_meta`
  ADD PRIMARY KEY (`umeta_id`),
  ADD UNIQUE KEY `uid_2` (`uid`,`meta_key`),
  ADD KEY `uid` (`uid`),
  ADD KEY `meta_key` (`meta_key`(191));

--
-- Indexes for table `user_plans`
--
ALTER TABLE `user_plans`
  ADD PRIMARY KEY (`uplid`);

--
-- Indexes for table `vps`
--
ALTER TABLE `vps`
  ADD PRIMARY KEY (`vpsid`),
  ADD KEY `uid` (`uid`) USING BTREE;

--
-- Indexes for table `vpsbackup_settings`
--
ALTER TABLE `vpsbackup_settings`
  ADD PRIMARY KEY (`vbid`),
  ADD UNIQUE KEY `serid` (`serid`);

--
-- Indexes for table `vps_meta`
--
ALTER TABLE `vps_meta`
  ADD PRIMARY KEY (`vmeta_id`),
  ADD UNIQUE KEY `vps_uuid_2` (`vps_uuid`,`meta_key`),
  ADD KEY `vps_uuid` (`vps_uuid`),
  ADD KEY `meta_key` (`meta_key`(191));

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admin_acl`
--
ALTER TABLE `admin_acl`
  MODIFY `aclid` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `admin_notes`
--
ALTER TABLE `admin_notes`
  MODIFY `noteid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `api`
--
ALTER TABLE `api`
  MODIFY `idapi` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `api_log`
--
ALTER TABLE `api_log`
  MODIFY `id` int(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `backups`
--
ALTER TABLE `backups`
  MODIFY `bkid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `backup_plans`
--
ALTER TABLE `backup_plans`
  MODIFY `bpid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `backup_servers`
--
ALTER TABLE `backup_servers`
  MODIFY `bid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `disks`
--
ALTER TABLE `disks`
  MODIFY `did` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `dnsplans`
--
ALTER TABLE `dnsplans`
  MODIFY `dnsplid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `email_templates`
--
ALTER TABLE `email_templates`
  MODIFY `eid` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `enduser_backup_servers`
--
ALTER TABLE `enduser_backup_servers`
  MODIFY `bserid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `enduser_iso`
--
ALTER TABLE `enduser_iso`
  MODIFY `isoid` int(5) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `firewall_plans`
--
ALTER TABLE `firewall_plans`
  MODIFY `fwid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `haproxy`
--
ALTER TABLE `haproxy`
  MODIFY `id` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `invoices`
--
ALTER TABLE `invoices`
  MODIFY `invoid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `ippool`
--
ALTER TABLE `ippool`
  MODIFY `ippid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `ips`
--
ALTER TABLE `ips`
  MODIFY `ipid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `ip_logs`
--
ALTER TABLE `ip_logs`
  MODIFY `iplid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `lb_ssl_certs`
--
ALTER TABLE `lb_ssl_certs`
  MODIFY `ssl_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `load_balancer`
--
ALTER TABLE `load_balancer`
  MODIFY `lbid` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `logs_admin`
--
ALTER TABLE `logs_admin`
  MODIFY `actid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `logs_vps`
--
ALTER TABLE `logs_vps`
  MODIFY `actid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `media_groups`
--
ALTER TABLE `media_groups`
  MODIFY `mgid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `notifications`
--
ALTER TABLE `notifications`
  MODIFY `nid` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `osreinstall`
--
ALTER TABLE `osreinstall`
  MODIFY `osrid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `passthrough`
--
ALTER TABLE `passthrough`
  MODIFY `pid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `pdns`
--
ALTER TABLE `pdns`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `plans`
--
ALTER TABLE `plans`
  MODIFY `plid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `pricing`
--
ALTER TABLE `pricing`
  MODIFY `prid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `recipes`
--
ALTER TABLE `recipes`
  MODIFY `rid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `self_shutdown`
--
ALTER TABLE `self_shutdown`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `servers`
--
ALTER TABLE `servers`
  MODIFY `serid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `server_groups`
--
ALTER TABLE `server_groups`
  MODIFY `sgid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `smartctl_devices`
--
ALTER TABLE `smartctl_devices`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `ssh_keys`
--
ALTER TABLE `ssh_keys`
  MODIFY `keyid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `storage`
--
ALTER TABLE `storage`
  MODIFY `stid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tasks`
--
ALTER TABLE `tasks`
  MODIFY `actid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tax_rules`
--
ALTER TABLE `tax_rules`
  MODIFY `id` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tmp_transactions`
--
ALTER TABLE `tmp_transactions`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `transactions`
--
ALTER TABLE `transactions`
  MODIFY `trid` int(12) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `usage`
--
ALTER TABLE `usage`
  MODIFY `usid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `uid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `user_meta`
--
ALTER TABLE `user_meta`
  MODIFY `umeta_id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `user_plans`
--
ALTER TABLE `user_plans`
  MODIFY `uplid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vps`
--
ALTER TABLE `vps`
  MODIFY `vpsid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vpsbackup_settings`
--
ALTER TABLE `vpsbackup_settings`
  MODIFY `vbid` int(10) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `vps_meta`
--
ALTER TABLE `vps_meta`
  MODIFY `vmeta_id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
