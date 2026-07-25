<?php

/**
 * Parses a date string in Indonesian format and converts it to a standard date format.
 *
 * @param string $dateStr The date string in Indonesian format (e.g., "31 Desember 2023").
 * @return string|null Returns the date in 'Y-m-d' format or null if parsing fails.
 */
function parse_indonesian_date($dateStr)
{
    $months = [
        'Januari' => 'January',
        'Februari' => 'February',
        'Maret' => 'March',
        'April' => 'April',
        'Mei' => 'May',
        'Juni' => 'June',
        'Juli' => 'July',
        'Agustus' => 'August',
        'September' => 'September',
        'Oktober' => 'October',
        'November' => 'November',
        'Desember' => 'December'
    ];
    // Replace Indonesian month with English
    $dateStr = str_ireplace(array_keys($months), array_values($months), $dateStr);
    $dt = DateTime::createFromFormat('d F Y', $dateStr);
    return $dt ? $dt->format('Y-m-d') : null;
}
/**
 * A helper function to clean and convert Indonesian-formatted number strings to floats.
 * It removes '.' as a thousand separator and replaces ',' with '.' for decimals.
 *
 * @param string $string The number string to clean.
 * @return float The cleaned number as a float.
 */
function format_indonesian_number(string $string): float
{
    // Remove thousand separator '.'
    $string = str_replace('.', '', $string);
    // Replace decimal separator ',' with '.'
    $string = str_replace(',', '.', $string);
    // Convert to float
    return (float) $string;
}
