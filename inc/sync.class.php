<?php

class PluginCertificateinventorySync extends CommonDBTM {

    /**
     * Expected software format generated on Ubuntu:
     *
     * name:
     *   GLPI-CERT::<CN>
     *
     * version:
     *   exp=YYYY-MM-DD;serial=HEX;fp=SHA256HEX;path=/path/to/cert
     *
     * publisher:
     *   issuer string
     *
     * The plugin converts that inventory marker into a native GLPI Certificate.
     */

    public static function cronInfo($name) {
        if ($name === 'sync') {
            return [
                'description' => 'Synchronize SSL/TLS certificates from inventory marker software'
            ];
        }
        return [];
    }

    public static function cronSync($task = null) {
        $count = self::scanAll();
        if ($task) {
            $task->addVolume($count);
            $task->log("Certificate Inventory: synchronized {$count} relation(s)\n");
        }
        return 1;
    }

    public static function scanAll(): int {
        global $DB;

        $count = 0;

        $iterator = $DB->request([
            'SELECT' => [
                'glpi_computers_softwareversions.id AS rel_id',
                'glpi_computers_softwareversions.computers_id',
                'glpi_computers_softwareversions.softwareversions_id'
            ],
            'FROM' => 'glpi_computers_softwareversions',
            'INNER JOIN' => [
                'glpi_softwareversions' => [
                    'ON' => [
                        'glpi_computers_softwareversions' => 'softwareversions_id',
                        'glpi_softwareversions' => 'id'
                    ]
                ],
                'glpi_softwares' => [
                    'ON' => [
                        'glpi_softwareversions' => 'softwares_id',
                        'glpi_softwares' => 'id'
                    ]
                ]
            ],
            'WHERE' => [
                ['glpi_softwares.name', 'LIKE', 'GLPI-CERT::%'],
                'glpi_computers_softwareversions.is_deleted' => 0
            ]
        ]);

        foreach ($iterator as $row) {
            $relation = new Computer_SoftwareVersion();
            if ($relation->getFromDB((int)$row['rel_id'])) {
                if (self::processRelation($relation)) {
                    $count++;
                }
            }
        }

        return $count;
    }

    public static function processRelation(Computer_SoftwareVersion $relation): bool {
        global $DB;

        $computerId = (int)($relation->fields['computers_id'] ?? 0);
        $softwareVersionId = (int)($relation->fields['softwareversions_id'] ?? 0);

        if (!$computerId || !$softwareVersionId) {
            return false;
        }

        $version = new SoftwareVersion();
        if (!$version->getFromDB($softwareVersionId)) {
            return false;
        }

        $software = new Software();
        if (!$software->getFromDB((int)$version->fields['softwares_id'])) {
            return false;
        }

        $name = (string)($software->fields['name'] ?? '');
        if (strpos($name, 'GLPI-CERT::') !== 0) {
            return false;
        }

        $computer = new Computer();
        if (!$computer->getFromDB($computerId)) {
            return false;
        }

        $cn = trim(substr($name, strlen('GLPI-CERT::')));
        $meta = self::parseMetadata((string)($version->fields['name'] ?? ''));

        if (empty($meta['exp'])) {
            return false;
        }

        $fingerprint = strtoupper(preg_replace('/[^A-Fa-f0-9]/', '', (string)($meta['fp'] ?? '')));
        $serial = strtoupper(preg_replace('/[^A-Fa-f0-9]/', '', (string)($meta['serial'] ?? '')));

        // The publisher is the issuer in our marker software.
        $issuer = trim((string)($software->fields['publisher'] ?? ''));

        $entityId = (int)($computer->fields['entities_id'] ?? 0);

        // Prefer fingerprint. Fall back to CN + expiration when fingerprint is absent.
        $certificateId = self::findCertificate($fingerprint, $cn, $meta['exp'], $entityId);

        $commentLines = [
            'Inventariado automáticamente por Certificate Inventory.',
            'CN: ' . $cn,
            'Emisor: ' . $issuer,
            'Serial: ' . $serial,
            'SHA256: ' . ($meta['fp'] ?? ''),
            'Ruta: ' . ($meta['path'] ?? ''),
            'Origen: GLPI Agent / software marker'
        ];
        if (!empty($meta['san'])) {
            $commentLines[] = 'SAN: ' . $meta['san'];
        }

        $certificateInput = [
            'name'            => $cn !== '' ? $cn : 'Certificado TLS',
            'entities_id'     => $entityId,
            'is_recursive'    => 0,
            'date_expiration' => $meta['exp'],
            'comment'         => implode("\n", $commentLines),
        ];

        // GLPI Certificate includes dns_name in GLPI 10.x.
        if ($cn !== '') {
            $certificateInput['dns_name'] = $cn;
        }

        $certificate = new Certificate();

        if ($certificateId) {
            $certificateInput['id'] = $certificateId;
            $certificate->update($certificateInput);
        } else {
            $certificateId = (int)$certificate->add($certificateInput);
            if (!$certificateId) {
                return false;
            }
        }

        self::ensureLink($certificateId, $computerId);
        self::remember($computerId, $softwareVersionId, $certificateId, $fingerprint);

        return true;
    }

    private static function parseMetadata(string $raw): array {
        // Expected: exp=2026-10-29;serial=...;fp=...;path=...;san=...
        $out = [];
        foreach (explode(';', $raw) as $part) {
            $pair = explode('=', $part, 2);
            if (count($pair) === 2) {
                $out[trim($pair[0])] = trim($pair[1]);
            }
        }
        return $out;
    }

    private static function findCertificate(string $fingerprint, string $cn, string $expiration, int $entityId): int {
        global $DB;

        // First consult our own mapping table.
        if ($fingerprint !== '') {
            $it = $DB->request([
                'SELECT' => ['certificates_id'],
                'FROM'   => 'glpi_plugin_certificateinventory_seen',
                'WHERE'  => ['fingerprint' => $fingerprint],
                'LIMIT'  => 1
            ]);
            foreach ($it as $row) {
                $id = (int)$row['certificates_id'];
                $cert = new Certificate();
                if ($id && $cert->getFromDB($id)) {
                    return $id;
                }
            }
        }

        // Safe fallback using native fields.
        $it = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => 'glpi_certificates',
            'WHERE'  => [
                'name'            => $cn,
                'date_expiration' => $expiration,
                'entities_id'     => $entityId,
                'is_deleted'      => 0
            ],
            'LIMIT' => 1
        ]);
        foreach ($it as $row) {
            return (int)$row['id'];
        }

        return 0;
    }

    private static function ensureLink(int $certificateId, int $computerId): void {
        $link = new Certificate_Item();

        if (!$link->getFromDBbyCertificatesAndItem($certificateId, $computerId, Computer::class)) {
            $link->add([
                'certificates_id' => $certificateId,
                'items_id'        => $computerId,
                'itemtype'        => Computer::class
            ]);
        }
    }

    private static function remember(
        int $computerId,
        int $softwareVersionId,
        int $certificateId,
        string $fingerprint
    ): void {
        global $DB;

        $existing = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => 'glpi_plugin_certificateinventory_seen',
            'WHERE'  => [
                'computers_id'        => $computerId,
                'softwareversions_id' => $softwareVersionId
            ],
            'LIMIT' => 1
        ]);

        foreach ($existing as $row) {
            $DB->update(
                'glpi_plugin_certificateinventory_seen',
                [
                    'certificates_id' => $certificateId,
                    'fingerprint'     => $fingerprint,
                    'date_mod'        => date('Y-m-d H:i:s')
                ],
                ['id' => (int)$row['id']]
            );
            return;
        }

        $DB->insert(
            'glpi_plugin_certificateinventory_seen',
            [
                'computers_id'        => $computerId,
                'softwareversions_id' => $softwareVersionId,
                'certificates_id'     => $certificateId,
                'fingerprint'         => $fingerprint,
                'date_mod'            => date('Y-m-d H:i:s')
            ]
        );
    }
}
