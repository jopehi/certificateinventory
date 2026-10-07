<?php

define('PLUGIN_CERTIFICATEINVENTORY_VERSION', '0.1.0');
define('PLUGIN_CERTIFICATEINVENTORY_MIN_GLPI', '10.0.0');
define('PLUGIN_CERTIFICATEINVENTORY_MAX_GLPI', '10.1.0');

function plugin_init_certificateinventory() {
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['certificateinventory'] = true;

    // React when inventory links a software version to a computer.
    $PLUGIN_HOOKS['item_add']['certificateinventory'] = [
        'Computer_SoftwareVersion' => 'plugin_certificateinventory_item_add'
    ];

    $PLUGIN_HOOKS['item_update']['certificateinventory'] = [
        'Computer_SoftwareVersion' => 'plugin_certificateinventory_item_update'
    ];

    // Add a config page mainly to allow a manual rescan.
    $PLUGIN_HOOKS['config_page']['certificateinventory'] = 'front/config.php';
}

function plugin_version_certificateinventory() {
    return [
        'name'           => 'Certificate Inventory',
        'version'        => PLUGIN_CERTIFICATEINVENTORY_VERSION,
        'author'         => 'UNAD / CSIRT',
        'license'        => 'GPL-3.0',
        'homepage'       => 'https://tics-solutions.xyz/glpi-plugins/certificateinventory/',
        'requirements'   => [
            'glpi' => [
                'min' => PLUGIN_CERTIFICATEINVENTORY_MIN_GLPI,
                'max' => PLUGIN_CERTIFICATEINVENTORY_MAX_GLPI,
            ]
        ]
    ];
}

function plugin_certificateinventory_check_prerequisites() {
    if (version_compare(GLPI_VERSION, PLUGIN_CERTIFICATEINVENTORY_MIN_GLPI, '<')) {
        echo 'GLPI >= ' . PLUGIN_CERTIFICATEINVENTORY_MIN_GLPI . ' required';
        return false;
    }
    if (version_compare(GLPI_VERSION, PLUGIN_CERTIFICATEINVENTORY_MAX_GLPI, '>=')) {
        echo 'This build targets GLPI 10.0.x';
        return false;
    }
    return true;
}

function plugin_certificateinventory_check_config($verbose = false) {
    return true;
}
