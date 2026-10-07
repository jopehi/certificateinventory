<?php

function plugin_certificateinventory_install() {
    global $DB;

    $migration = new Migration(100);

    if (!$DB->tableExists('glpi_plugin_certificateinventory_seen')) {
        $query = "CREATE TABLE `glpi_plugin_certificateinventory_seen` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `computers_id` int unsigned NOT NULL DEFAULT 0,
            `softwareversions_id` int unsigned NOT NULL DEFAULT 0,
            `certificates_id` int unsigned NOT NULL DEFAULT 0,
            `fingerprint` varchar(128) NOT NULL DEFAULT '',
            `date_mod` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_computer_version` (`computers_id`,`softwareversions_id`),
            KEY `computers_id` (`computers_id`),
            KEY `certificates_id` (`certificates_id`),
            KEY `fingerprint` (`fingerprint`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
        $DB->doQuery($query);
    }

    // Register a cron task for periodic reconciliation.
    CronTask::Register(
        'PluginCertificateinventorySync',
        'sync',
        DAY_TIMESTAMP,
        [
            'comment' => 'Synchronize SSL/TLS certificates detected by GLPI Agent',
            'mode'    => CronTask::MODE_EXTERNAL
        ]
    );

    return true;
}

function plugin_certificateinventory_uninstall() {
    global $DB;

    if ($DB->tableExists('glpi_plugin_certificateinventory_seen')) {
        $DB->doQuery("DROP TABLE `glpi_plugin_certificateinventory_seen`");
    }
    return true;
}

function plugin_certificateinventory_item_add($item) {
    if ($item instanceof Computer_SoftwareVersion) {
        PluginCertificateinventorySync::processRelation($item);
    }
}

function plugin_certificateinventory_item_update($item) {
    if ($item instanceof Computer_SoftwareVersion) {
        PluginCertificateinventorySync::processRelation($item);
    }
}
