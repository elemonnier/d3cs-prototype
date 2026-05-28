#!/bin/bash

usage() {
    cat <<EOF
  Usage: mkosmap.sh [-<option>...] <lat1> <lon1> <lat2> <lon2> <zoom> [<output_prefix>]
     or  mkosmap.sh [-<option>...] <lat1> <lon1> <width> <height> <zoom> [<output_prefix>]
  
  Example: mkosmap.sh -fr 47.64447 -2.74458 47.65078 -2.73641 17 tohannic
  Example: mkosmap.sh -light -noosm 47.64531 -2.77153 800 600 15 kercado
  
  Build from OSM tiles a bitmap image representing a rectangular area and download the 
  corresponding OSM data. The two corners (in any order) of the area must be given as 
  longitute and latitude in decimal degrees (lat1, lon1) and (lat2, lon2).
  Alternatively, one can provide the latitude and longitude of the center and the size
  of the image (width and height in pixels). The presence of a decimal point in the third
  parameter tells which alternative is chosen.
  
  Options can be used to specify the syle of the image (std, cycle, transport, hot, bw, 
  light, dark, shading, fr, de) and to avoid providing some of the ouput :
    nopng : prevents the generation of the bitmap image <output_prefix>.png 
    noosm : prevents the generation of the osm file <output_prefix>.osm 
    noarea : prevents the generation of the bounding box file <output_prefix>.area
  
  Option noeven prevents reducing the resulting image width and eight to even values. 
  As some codecs that are used to build videos from still images (i.e. H264) do not support 
  uneven image widths and heights, by default the width and the height of the produced image 
  is truncated to the nearer lower even values, thus possibly reducing the width and/or 
  height by 1 pixel. 
  
  The zoom is comprised between 0 and 18 (up to 19 for the std style, up to 20 
  for the fr style)
  
  Depends on ImageMagick (montage, convert), bc and awk

  Bugs: 
   - Errors in arguments are poorly handled.
   - Tile servers may cease to give free access to their tiles, so an image style may 
     become unusable. This is not tested and may induce various errors.
   - In case tile downloading does not function properly, empty image files are built
     and an error occurs when assembling the tiles, with somehow strange error messages.
EOF
    exit 1
}

if [ $# == 0 ] ; then
    usage
fi



TILE_SERVER=http://a.tile.openstreetmap.org
STYLE="std"

# By default produce all
PRODUCE_PNG=true
PRODUCE_OSM=true
PRODUCE_AREA=true
TRUNCATE_TO_EVEN=true


while [[ ${1} == -* ]]
 do
  echo option $1
  case "$1" in   
   "-std")
        shift
        ;;
   "-cycle")
        TILE_SERVER=http://a.tile2.opencyclemap.org/cycle
        STYLE="cycle"
        shift
        ;;
   "-transport")
      TILE_SERVER=http://a.tile2.opencyclemap.org/transport
        STYLE="transport"
        shift
        ;;
   "-hot")
        TILE_SERVER=http://a.tile.openstreetmap.fr/hot
        STYLE="hot"
        shift
        ;;
   "-mapquest")
        TILE_SERVER=http://otile1.mqcdn.com/tiles/1.0.0/osm
        STYLE="mapquest"
        shift
        ;;
   "-light")
        TILE_SERVER=http://a.basemaps.cartocdn.com/light_all
        STYLE="light"
        shift
        ;;
   "-dark")
        TILE_SERVER=http://a.basemaps.cartocdn.com/dark_all
        STYLE="dark"
        shift
        ;;
    "-shading")
        TILE_SERVER=http://c.tiles.wmflabs.org/hillshading
        STYLE="shading"
        shift
        ;;
   "-de")
        TILE_SERVER=http://a.tile.openstreetmap.de/tiles/osmde
        STYLE="de"
        shift
        ;;
   "-bw")
        TILE_SERVER=https://tiles.wmflabs.org/bw-mapnik
        STYLE="bw"
        shift
        ;;
   "-fr")
        TILE_SERVER=http://a.tile.openstreetmap.fr/osmfr
        STYLE="fr"
        shift
        ;;
   "-nopng")
      PRODUCE_PNG=false
      shift
      ;;
  "-noosm")
      PRODUCE_OSM=false
      shift
      ;;
  "-noarea")
      PRODUCE_AREA=false
      shift
      ;;
  "-noeven")
      TRUNCATE_TO_EVEN=false
      shift
      ;;
  *)
      usage
      ;;
 esac

done
       


DEFAULT_OUTPUT=mkosmap
CACHE_DIR=/tmp/mkosmap/$STYLE

export LANG=C


#############################################################################################

min() 
{
 (( $(echo "$1 < $2" | bc -l) )) && echo $1 || echo $2 
}

max() {
 (( $(echo "$1 > $2" | bc -l) )) && echo $1 || echo $2 
}


floor() {
  printf '%.*f' 0 $(echo "$1 - 0.5" | bc -l)
}


xpixel2long()
{
 _xpixel=$1
 _zoomc=$(($2 + 8))
 echo $(xtile2long ${_xpixel} ${_zoomc})
}

xtile2long()
{
 _xtile=$1
 _zoom=$2
 echo "${_xtile} ${_zoom}" | awk '{printf("%.9f", $1 / 2.0^$2 * 360.0 - 180)}'
} 


ypixel2lat()
{
 _ypixel=$1
 _zoomc=$(($2 + 8))
 echo $(ytile2lat ${_ypixel} ${_zoomc})
}

ytile2lat()
{
 _ytile=$1
 _zoom=$2
 _lat=`echo "${_ytile} ${_zoom}" | awk -v PI=3.14159265358979323846 '{ 
       num_tiles = PI - 2.0 * PI * $1 / 2.0^$2;
       printf("%.9f", 180.0 / PI * atan2(0.5 * (exp(num_tiles) - exp(-num_tiles)),1)); }'`;
 echo "${_lat}";
}


long2xpixel()  
{ 
 _long=$1
 _zoomc=$(($2 + 8))
 echo $(long2xtile ${_long} ${_zoomc})
}


long2xtile()  
{ 
 _long=$1
 _zoom=$2
 x=`echo "${_long} ${_zoom}" | awk '{ x = ($1 + 180.0) / 360 * 2.0^$2;
  printf("%.9f", x) }'`
  echo $(floor ${x})
}


lat2ypixel() 
{ 
 _lat=$1
 _zoomc=$(($2 + 8))
 echo $(lat2ytile ${_lat} ${_zoomc})
}


lat2ytile() 
{ 
 _lat=$1
 _zoom=$2
 y=`echo "${_lat} ${_zoom}" | awk -v PI=3.14159265358979323846 '{ 
   tan_x=sin($1 * PI / 180.0)/cos($1 * PI / 180.0);
   y = (1 - log(tan_x + 1/cos($1 * PI/ 180))/PI)/2 * 2.0^$2; 
   printf("%.9f", y) }'`
 echo $(floor ${y})
}



#############################################################################################

zoom="$5"

if [[ $zoom < 1 || $zoom > 20 ]] ; then
    echo "Wrong zoom: $zoom"
    exit 2
fi


if [ "$6" != "" ] ; then
    output="$6"
else
    output="$DEFAULT_OUTPUT"
fi


if [[ "$3" != *"."* ]] ; then

    # Compute the bounding box from the center point and the size of the image
    echo "Bounding box computed from the center (lat=$1, long=$2) for a ${3}x${4} image"
    
    centerlat=$1
    centerlon=$2

    imgwidth=$3
    imgheight=$4

    cx=$(long2xpixel $centerlon $zoom)
    cy=$(lat2ypixel $centerlat $zoom)

    minx=$(( $cx - ($imgwidth / 2) ))
    maxx=$(( $cx + ($imgwidth / 2) ))
    miny=$(( $cy - ($imgheight / 2) ))
    maxy=$(( $cy + ($imgheight / 2) ))

    west=$(xpixel2long $minx $zoom)
    east=$(xpixel2long $maxx $zoom)
    north=$(ypixel2lat $miny $zoom)
    south=$(ypixel2lat $maxy $zoom)

else 
    south=$(min $1 $3)
    north=$(max $1 $3)
    west=$(min $2 $4)
    east=$(max $2 $4)
fi


echo "North = $north"
echo "South = $south"
echo "East  = $east"
echo "West  = $west"


##################################### PNG #####################################
if [ $PRODUCE_PNG == true ]; then
  
  mkdir -p ${CACHE_DIR}/${zoom} >& /dev/null
  
  
  # Ranks of the tiles
  x1=$(long2xtile $west $zoom)
  x2=$(long2xtile $east $zoom)
  
  y1=$(lat2ytile $north $zoom)
  y2=$(lat2ytile $south $zoom)
  
  # Number of tiles to download
  nbx=$((1 + $x2 - $x1))
  nby=$((1 + $y2 - $y1))

     
  echo -n "Dowloading ${nbx}x${nby}=$(($nbx * $nby)) $STYLE tiles at zoom $zoom, from ($x1, $y1) to ($x2, $y2) " 
  tilenames=""
  y=$y1
  while (($y <= $y2)) ; do
      x=$x1
      while (($x <= $x2)) ; do
  	echo -n "."
  	if [ ! -e  ${CACHE_DIR}/${zoom}/tile_${y}_${x}.png ] ; then
  	    wget -q -O ${CACHE_DIR}/${zoom}/tile_${y}_${x}.png $TILE_SERVER/$zoom/$x/$y.png
  	fi
  	tilenames="$tilenames ${CACHE_DIR}/${zoom}/tile_${y}_${x}.png"
  	((x+=1))
      done
      ((y+=1))
  done
  echo ""
  
  
  # Longitude and latitude of north-west corner of the first tile
  loncorner=$(xtile2long $x1 $zoom)
  latcorner=$(ytile2lat $y1 $zoom)
  
  # Pixel ranks of north-west corner of the first tile 
  pleftwest=$(long2xpixel $loncorner $zoom)
  ptopnorth=$(lat2ypixel $latcorner $zoom)
  
  # Pixel ranks of the user rectangle 
  pwest=$(long2xpixel $west $zoom)
  peast=$(long2xpixel $east $zoom)
  pnorth=$(lat2ypixel $north $zoom)
  psouth=$(lat2ypixel $south $zoom)

  # Pixel size and shift of the user rectangle in the outer tile montage
  if  [[ -v imgwidth ]] ; then
      sizex=${imgwidth}
      sizey=${imgheight}
  else  
     sizex=$(($peast - $pwest))
     sizey=$(($psouth - $pnorth))
  fi
  
  deltax=$(($pwest - $pleftwest))
  deltay=$(($pnorth - $ptopnorth))


  # Making the image width and eight even
  if [ $TRUNCATE_TO_EVEN == true ]; then
      evenx=$(( $sizex % 2 ))
      eveny=$(( $sizey % 2 ))
      if [[ $evenx == 1 || $eveny == 1 ]] ; then   
        echo -n "Truncating image dimensions to even values ${sizex}x${sizey} -> "
        if [[ $evenx == 1 ]] ; then sizex=$(($sizex - 1 )) ; fi
        if [[ $eveny == 1 ]] ; then sizey=$(($sizey - 1 )) ; fi
        echo ${sizex}x${sizey}
      fi
  fi

  # Building the montage
  echo "Building montage ${output}.png, cropping tiles to ${sizex}x${sizey}+${deltax}+${deltay} "
  montage $tilenames -tile ${nbx}x${nby} -geometry +0+0 png:- | convert -  -crop ${sizex}x${sizey}+${deltax}+${deltay} +repage "${output}.png"

fi



##################################### OSM #####################################
if [  $PRODUCE_OSM == true ]; then 
    echo "Downloading OSM data in ${output}.osm"
    url="http://overpass-api.de/api/interpreter?data=(node($south,$west,$north,$east);<;rel(br););out meta;"
  wget -O ${output}.osm "$url" > /dev/null
fi

    
##################################### AREA #####################################
if [ $PRODUCE_AREA == true ]; then 
  echo "Writing area in file ${output}.area"
  echo "geo:${south},${west},${north},${east}" > ${output}.area
fi
