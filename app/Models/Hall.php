<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Hall extends Model
{
    use HasFactory;

    protected $fillable = [
        'title', 'rows', 'places', 'normal_price', 'vip_price'
    ];

    public function sessions()
    {
        return $this->hasMany(Session::class);
    }

    public function placesList()
    {
        return $this->hasMany(Place::class);
    }
}
