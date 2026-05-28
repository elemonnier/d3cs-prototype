#!/bin/bash

usage() {
    cat <<EOF
Usage montage_duo.sh [-horiz|-vert] <label1> <dsrc1> <label2> <dsrc2> <ddest>
      montage_duo.sh [-horiz|-vert] <label1> <img1> <label2> <img2> <img_duo>

Build montages (frames + juxtaposition) of pairs of timestamped images taken
from two source directories. The two source directories <dsrc1> <dsrc2> are
assumed to contain timestamped images with the same resolution and named
img_xx...xx.png.  Images with the same timestamp in <dsrc1> and <dsrc2> are
paired, resulting in an image in <ddest> with this timestamp. For an image img
in <dsrc1> (resp.<dscr2>) with no correspondant in <dsrc2> (resp.<dscr1>), this
image img is juxtaposed with a new image that has the same content as the previous
(i.e. with the nearer lower timestamp) image in <dscr2> (resp. <dsrc1>),
resulting in an image in <ddest> with the timestamp of img.

Alternatively, the  parameters can be image filenames. In this case only one
montage is performed. Use this method to produce a duo background image,
often with the same source image repeated twice.

A text label is added below each part of the montage, according to
parameters <label1> and <label2> 

The layout of the montage is defined with option -horiz (default, the second image
is put on the right of the first one) or -vert (the second image is put below the 
first one).
EOF
    exit 1
}




if [ "$1" == "-h" ] ; then
    usage
    exit 0
fi

if (( $# != 5 && $# != 6 ))   ; then
    usage
    exit 0
fi

tile="2x1"
if [[ ${1} == "-horiz" ]] ; then
    tile="2x1"
    shift
fi
if [[ ${1} == "-vert" ]] ; then
    tile="1x2"
    shift
fi


labela="$1"
labelb="$3"

montageduo() {
    montage  -label "$labela" "$1" \
	     -label "$labelb" "$2" \
             -mattecolor skyblue  -background none \
	     -geometry +0+0 -frame 5  -tile $tile  png32:"$3"
}

  
max() {
    if (( $1 > $2 )) ; then
	echo $1
    else
	echo $2
    fi
}



# Only one image
if [ -f "$2" ] ; then
    montageduo "${2}" "${4}" "${5}" 
    echo Duo  $(identify -format "%wx%h" "${5}") image built.
    exit 0
fi



# Directory of images
dsrca=$(realpath "$2")
if [ ! -r "$dsrca" ] ; then
    echo "Cannot read directory $dsrca"
    exit 1
fi
dsrcb=$(realpath "$4")
if [ ! -r "$dsrcb" ] ; then
    echo "Cannot read directory $dsrcb"
    exit 1
fi
ddest=$(realpath "$5")
if [ ! -w "$ddest" ] ; then
    echo "$ddest not found or not writeable"
    exit 1
fi

cd "$dsrca"
filesa=( $(ls *.png) )
nbimga=${#filesa[@]} 

width=$(identify -format "%w" ${filesa[0]})
height=$(identify -format "%h" ${filesa[0]})
if [ $tile == "2x1" ] ; then
   # + 4 x frame size (used in montageduo())
   duo_width=$((  (2 * $width) + 20 ))
   # + 1 x label size (hard coded in montage)
   duo_height=$(( $height + 28 ))
else
   # + 1 x frame size (used in montageduo())
   duo_width=$(( $width + 10 ))
   # + 2 x label size (hard coded in montage)
   duo_height=$(( (2 * $height) + 56 ))
fi

cd "$dsrcb"
filesb=( $(ls *.png) )
nbimgb=${#filesb[@]} 



blank_img='xc:grey['${width}x${height}'!]'

   
echo -n  "Building at least $(max $nbimga $nbimgb) ${duo_width}x${duo_height} images"

pa="${blank_img}" ; pb="${blank_img}"
a=0; b=0

while (( $a < ${nbimga}  && $b < ${nbimgb} )) ; do

    ca=${filesa[$a]} ; cb=${filesb[$b]}

    stampa=${ca//[![:digit:]]/} ; stampb=${cb//[![:digit:]]/}

    if (( $stampa > $stampb  )) ; then
	montageduo "${pa}" "${dsrcb}/${cb}"  "${ddest}/${cb}"
	pb="${dsrcb}/${cb}"
	(( b++ ))
    elif (( $stampa < $stampb )) ; then
	montageduo "${dsrca}/${ca}" "${pb}"  "${ddest}/${ca}"
	pa="${dsrca}/${ca}"
	(( a++ ))
    else
	montageduo "${dsrca}/${ca}" "${dsrcb}/${cb}"  "${ddest}/${ca}"
	pa="${dsrca}/${ca}" ; pb="${dsrcb}/${cb}"
        (( a++ )) ; (( b++ ))
    fi
    
    echo -n .
	
done

# There are some images letf (only in dsrca or dsrcb)
# -> montage with the last corresponding image from the other side
while (( $a < ${nbimga} )) ; do
    ca=${filesa[$a]}
    convert "${pb}" -fill black -colorize 40% miff:- | montageduo "${dsrca}/${ca}" miff:-  "${ddest}/${ca}"
    (( a++ ))
    echo -n '-'
done
while (( $b < ${nbimgb} )) ; do
    cb=${filesb[$b]}
    convert "${pa}" -fill black -colorize 40% miff:- | montageduo miff:-  "${dsrcb}/${cb}"  "${ddest}/${cb}"
    (( b++ ))
    echo -n '+'
done


echo
