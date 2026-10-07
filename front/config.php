<?php

include('../../../inc/includes.php');

Session::checkRight('config', UPDATE);

Html::header('Certificate Inventory', $_SERVER['PHP_SELF'], 'config', 'plugins');

echo "<div class='center'>";
echo "<h2>Certificate Inventory</h2>";
echo "<p>Convierte marcadores GLPI-CERT inventariados por GLPI Agent en objetos Certificate nativos.</p>";

if (isset($_POST['rescan'])) {
    Session::checkCSRF();
    $count = PluginCertificateinventorySync::scanAll();
    Session::addMessageAfterRedirect("Sincronización completada: {$count} relación(es) procesada(s).", true, INFO);
    Html::redirect($_SERVER['PHP_SELF']);
}

echo "<form method='post'>";
echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
echo "<button class='btn btn-primary' type='submit' name='rescan' value='1'>Reprocesar inventario de certificados</button>";
echo "</form>";
echo "</div>";

Html::footer();
