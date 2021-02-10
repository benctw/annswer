<?php
session_start();
echo '<pre>';
var_dump($_SESSION);
echo '</pre>';

echo('<br>============<br>');
echo '<pre>';
var_dump($_SESSION['challenge']);
echo '</pre>';

echo('<br>============<br>');
echo '<pre>';
var_dump(unserialize(serialize($_SESSION['challenge'])));
echo '</pre>';

echo('<br>============<br>');
echo '<pre>';
var_dump(unserialize(base64_decode(base64_encode(serialize($_SESSION['challenge'])))));
echo '</pre>';


echo('<br>============<br>');
echo '<pre>';
var_dump($_SESSION['registrations']);
echo '</pre>';

echo('<br>============<br>');
echo '<pre>';
var_dump(unserialize(serialize($_SESSION['registrations'])));
echo '</pre>';

echo('<br>============<br>');
echo '<pre>';
var_dump(unserialize(base64_decode(base64_encode(serialize($_SESSION['registrations'])))));
echo '</pre>';


$arrRegistrations = unserialize(base64_decode(base64_encode(serialize($_SESSION['registrations']))));
if (is_array($arrRegistrations)) {
    // foreach ($_SESSION['registrations'] as $reg) {
    foreach ($arrRegistrations as $reg) {
        $ids[] = $reg->credentialId;
    }
}
echo(count($ids));




require_once ('../../../config.php');
$conn = new mysqli($strServer, $strDbUserID, $strPassword, $strDatabase);
$sql_query = "SELECT `id`, `fido2`, `fido2_challenge`, `fido2_registrations` 
                FROM `user` 
                WHERE `id` = 27;";   
$result_query = $conn->query($sql_query);
$conn->close();
$row_query = $result_query->fetch_assoc();
$strfido2_registrations_for_function = $row_query['fido2_registrations'];
$strfido2_challenge_for_function = $row_query['fido2_challenge'];



$arrRegistrations = unserialize(base64_decode(base64_encode(serialize($strfido2_registrations_for_function))));
if (is_array($arrRegistrations)) {
    // foreach ($_SESSION['registrations'] as $reg) {
    foreach ($arrRegistrations as $reg) {
        $ids[] = $reg->credentialId;
    }
}
echo(count($ids));


$arrRegistrations = unserialize(base64_decode($strfido2_registrations_for_function));
if (is_array($arrRegistrations)) {
    // foreach ($_SESSION['registrations'] as $reg) {
    foreach ($arrRegistrations as $reg) {
        $ids[] = $reg->credentialId;
    }
}
echo(count($ids));



$k="Tzo4OiJzdGRDbGFzcyI6NTp7czoxMjoiY3JlZGVudGlhbElkIjtzOjY0OiJhJ293WUNa+ZQnnfKAR3lWTy6mfksyihcG+jvkUIzamZ66hOc/poOXmAwaSAqi3UfKpFM0IotvdSmqdbedri0XIjtzOjE5OiJjcmVkZW50aWFsUHVibGljS2V5IjtzOjE3ODoiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFQmtuRUNIdHhtSXRhN1UyWG4wdzNndWNIOFVlNwpoSjUxTUNuck5LRzhQVmRUNkkyckxiNTd0RWUzVHhPcERiRUl0NTlpZVJ4WFhRazRKNmlCaXdydVJBPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCiI7czoxMToiY2VydGlmaWNhdGUiO3M6MTAxMzoiLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN2akNDQWFhZ0F3SUJBZ0lFZEliOXdqQU5CZ2txaGtpRzl3MEJBUXNGQURBdU1Td3dLZ1lEVlFRREV5TloKZFdKcFkyOGdWVEpHSUZKdmIzUWdRMEVnVTJWeWFXRnNJRFExTnpJd01EWXpNVEFnRncweE5EQTRNREV3TURBdwpNREJhR0E4eU1EVXdNRGt3TkRBd01EQXdNRm93YnpFTE1Ba0dBMVVFQmhNQ1UwVXhFakFRQmdOVkJBb01DVmwxClltbGpieUJCUWpFaU1DQUdBMVVFQ3d3WlFYVjBhR1Z1ZEdsallYUnZjaUJCZEhSbGMzUmhkR2x2YmpFb01DWUcKQTFVRUF3d2ZXWFZpYVdOdklGVXlSaUJGUlNCVFpYSnBZV3dnTVRrMU5UQXdNemcwTWpCWk1CTUdCeXFHU000OQpBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJKVmQ4NjMzSkgweGRlLzluTVR6R2s2SGpycmhnUWxXWVZEN09Jc3VYMlVuCnYxZEFtcVdCcFEwS3hTOFlSRndLRTFTS0UxUElwT1dhY0U1U084Qk42KzJqYkRCcU1DSUdDU3NHQVFRQmdzUUsKQWdRVk1TNHpMall1TVM0MExqRXVOREUwT0RJdU1TNHhNQk1HQ3lzR0FRUUJndVVjQWdFQkJBUURBZ1VnTUNFRwpDeXNHQVFRQmd1VWNBUUVFQkJJRUVQaWdFZk9NQ2swVmdBWVhFUitlM0gwd0RBWURWUjBUQVFIL0JBSXdBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQU1WeElnT2FhVW40NFpvbTlhZjBLcUc5SjY1NU9oVVZCVlcrcTBBczYKQUlvZDNBSDViSGIyYURZYWtlSXl5QkNubkdNSFRKdHVla2JySGJYWVhFUkluNGFLZGtQU0tseUdMc0EvQStXRQppK09BZlhyTlZmamhyaDdpRTZ4enEwc2c0L3ZWSm95d2U0ZUFKeDBmUytEbDNheHpUVHBZbDcxTmM3cC9OWDZpCkNNbWRpazBwQXVZSmVnQmNUY2tFM0FvWUVnNEs5OUFNL0phYUtJYmxzYkZoOCszTHhuZW1lTmY3VXdPY3phR0cKdmpTNlV6R1ZJME9kZjlsS2NQSXdZaHVUeE01Q2FOTVhUWlE3eHE0L3lUZkMza1BXdEU0aEZUMzRVSkpmbFpCaQpMcnhHNE9zWXhrSHcvbjV2S2dtcHNwQjNHZll1WVRXaGtES2lFOENZdHlnODdnPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQoiO3M6MTY6InNpZ25hdHVyZUNvdW50ZXIiO2k6MTI1O3M6NjoiQUFHVUlEIjtzOjE2OiL4oBHzjApNFYAGFxEfntx9Ijt9";
$arrRegistrations = unserialize(base64_decode($k));
echo '<pre>';
var_dump($arrRegistrations);
echo '</pre>';
if (is_array($arrRegistrations)) {
    // foreach ($_SESSION['registrations'] as $reg) {
    foreach ($arrRegistrations as $reg) {
        $ids[] = $reg->credentialId;
    }
}
echo(count($ids));

?>