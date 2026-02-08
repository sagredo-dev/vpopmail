--
-- Database: `vpopmail`
--
CREATE DATABASE IF NOT EXISTS `vpopmail` DEFAULT CHARACTER SET latin1 COLLATE latin1_swedish_ci;
USE `vpopmail`;

-- --------------------------------------------------------

--
-- Table `aliasdomains`
--

CREATE TABLE IF NOT EXISTS `aliasdomains` (
  `alias` varchar(96) NOT NULL,
  `domain` varchar(96) NOT NULL,
  PRIMARY KEY (`alias`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table `dir_control`
--

CREATE TABLE IF NOT EXISTS `dir_control` (
  `domain` varchar(96) NOT NULL,
  `cur_users` int(11) DEFAULT NULL,
  `level_cur` int(11) DEFAULT NULL,
  `level_max` int(11) DEFAULT NULL,
  `level_start0` int(11) DEFAULT NULL,
  `level_start1` int(11) DEFAULT NULL,
  `level_start2` int(11) DEFAULT NULL,
  `level_end0` int(11) DEFAULT NULL,
  `level_end1` int(11) DEFAULT NULL,
  `level_end2` int(11) DEFAULT NULL,
  `level_mod0` int(11) DEFAULT NULL,
  `level_mod1` int(11) DEFAULT NULL,
  `level_mod2` int(11) DEFAULT NULL,
  `level_index0` int(11) DEFAULT NULL,
  `level_index1` int(11) DEFAULT NULL,
  `level_index2` int(11) DEFAULT NULL,
  `the_dir` varchar(160) DEFAULT NULL,
  PRIMARY KEY (`domain`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table `lastauth`
--

CREATE TABLE IF NOT EXISTS `lastauth` (
  `user` varchar(32) NOT NULL,
  `domain` varchar(96) NOT NULL,
  `remote_ip` varchar(39) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`user`,`domain`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table `limits`
--

CREATE TABLE IF NOT EXISTS `limits` (
  `domain` varchar(96) NOT NULL,
  `maxpopaccounts` int(10) NOT NULL DEFAULT -1,
  `maxaliases` int(10) NOT NULL DEFAULT -1,
  `maxforwards` int(10) NOT NULL DEFAULT -1,
  `maxautoresponders` int(10) NOT NULL DEFAULT -1,
  `maxmailinglists` int(10) NOT NULL DEFAULT -1,
  `diskquota` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `maxmsgcount` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `defaultquota` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `defaultmaxmsgcount` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `disable_pop` tinyint(1) NOT NULL DEFAULT 0,
  `disable_imap` tinyint(1) NOT NULL DEFAULT 0,
  `disable_dialup` tinyint(1) NOT NULL DEFAULT 0,
  `disable_passwordchanging` tinyint(1) NOT NULL DEFAULT 0,
  `disable_webmail` tinyint(1) NOT NULL DEFAULT 0,
  `disable_relay` tinyint(1) NOT NULL DEFAULT 0,
  `disable_smtp` tinyint(1) NOT NULL DEFAULT 0,
  `disable_spamassassin` tinyint(1) NOT NULL DEFAULT 0,
  `delete_spam` tinyint(1) NOT NULL DEFAULT 0,
  `disable_maildrop` tinyint(1) NOT NULL DEFAULT 0,
  `perm_account` tinyint(2) NOT NULL DEFAULT 0,
  `perm_alias` tinyint(2) NOT NULL DEFAULT 0,
  `perm_forward` tinyint(2) NOT NULL DEFAULT 0,
  `perm_autoresponder` tinyint(2) NOT NULL DEFAULT 0,
  `perm_maillist` tinyint(4) NOT NULL DEFAULT 0,
  `perm_quota` tinyint(2) NOT NULL DEFAULT 0,
  `perm_defaultquota` tinyint(2) NOT NULL DEFAULT 0,
  PRIMARY KEY (`domain`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table `valias`
--

CREATE TABLE IF NOT EXISTS `valias` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `valias_type` tinyint(1) NOT NULL DEFAULT 1 COMMENT '1=forwarder 0=lda',
  `alias` varchar(32) NOT NULL,
  `domain` varchar(96) NOT NULL,
  `valias_line` text NOT NULL,
  `copy` tinyint(1) NOT NULL DEFAULT 0 COMMENT '0=redirect 1=copy&redirect',
  PRIMARY KEY (`id`),
  KEY `alias` (`alias`,`domain`,`valias_type`) USING BTREE,
  KEY `alias_2` (`alias`,`domain`)
) ENGINE=MyISAM AUTO_INCREMENT=250 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table `vlog`
--

CREATE TABLE IF NOT EXISTS `vlog` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user` varchar(32) DEFAULT NULL,
  `passwd` varchar(32) DEFAULT NULL,
  `domain` varchar(96) DEFAULT NULL,
  `logon` varchar(200) DEFAULT NULL,
  `remoteip` varchar(39) DEFAULT NULL,
  `message` varchar(255) DEFAULT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `error` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_idx` (`user`),
  KEY `domain_idx` (`domain`),
  KEY `remoteip_idx` (`remoteip`),
  KEY `error_idx` (`error`),
  KEY `message_idx` (`message`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table `vpopmail`
--

CREATE TABLE IF NOT EXISTS `vpopmail` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `pw_name` varchar(64) NOT NULL,
  `pw_domain` varchar(96) NOT NULL,
  `pw_passwd` varchar(128) DEFAULT NULL,
  `my_uid` tinyint(4) NOT NULL DEFAULT 89,
  `my_gid` tinyint(4) NOT NULL DEFAULT 89,
  `pw_uid` int(11) DEFAULT NULL,
  `pw_gid` int(11) DEFAULT NULL,
  `pw_gecos` varchar(64) DEFAULT NULL,
  `pw_dir` varchar(160) DEFAULT NULL,
  `pw_shell` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`pw_name`,`pw_domain`),
  UNIQUE KEY `id` (`id`),
  KEY `pw_domain` (`pw_domain`)
) ENGINE=InnoDB AUTO_INCREMENT=175 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci ROW_FORMAT=DYNAMIC;
