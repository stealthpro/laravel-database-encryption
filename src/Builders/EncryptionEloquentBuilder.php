<?php
/**
 * src/Builders/EncryptionEloquentBuilder.php.
 *
 */

namespace ESolution\DBEncryption\Builders;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\PostgresConnection;
use Illuminate\Support\Facades\DB;

class EncryptionEloquentBuilder extends Builder
{

    public function whereEncrypted($param1, $param2, $param3 = null)
    {
        $filter            = new \stdClass();
        $filter->field     = $param1;
        $filter->operation = isset($param3) ? $param2 : '=';
        $filter->value     = isset($param3) ? $param3 : $param2;

        $salt = substr(hash('sha256',
            config('laravelDatabaseEncryption.encrypt_key')), 0, 16);

        if (DB::connection() instanceof MySqlConnection) {
            return self::whereRaw("CONVERT(AES_DECRYPT(FROM_bASE64(`{$filter->field}`), '{$salt}') USING utf8mb4) {$filter->operation} ? ",
                [$filter->value]);
        } elseif (DB::connection() instanceof PostgresConnection) {
            return self::whereRaw("encode(decrypt(decode({$filter->field}, 'base64'), {$salt}, 'aes-ecb'), 'escape') {$filter->operation} ? ",
                [$filter->value]);
        }
    }

    public function orWhereEncrypted($param1, $param2, $param3 = null)
    {
        $filter            = new \stdClass();
        $filter->field     = $param1;
        $filter->operation = isset($param3) ? $param2 : '=';
        $filter->value     = isset($param3) ? $param3 : $param2;

        $salt = substr(hash('sha256',
            config('laravelDatabaseEncryption.encrypt_key')), 0, 16);

        if (DB::connection() instanceof MySqlConnection) {
            return self::orWhereRaw("CONVERT(AES_DECRYPT(FROM_bASE64(`{$filter->field}`), '{$salt}') USING utf8mb4) {$filter->operation} ? ",
                [$filter->value]);
        } elseif (DB::connection() instanceof PostgresConnection) {
            return self::orWhereRaw("encode(decrypt(decode({$filter->field}, 'base64'), '{$salt}', 'aes-ecb'), 'escape') {$filter->operation} ? ",
                [$filter->value]);
        }
    }

}
