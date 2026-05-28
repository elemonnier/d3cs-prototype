#!/bin/bash


usage() {
 cat <<EOF
mkmovie.sh    Makes a movie from a set of timestamped PNG images

Usage:  mkmovie.sh [-h] [-option optarg]

Options
  -h 
      Prints out this help

  -b background_image
      The image to be added as a background of the movie
      Default: no background

  -a acceleration
      The acceleration factor (integer) to be applied to the set of images.
      This impacts the duration considered between two successive images 
      (i.e., the gap between their timestamp), before building the video.
      Default: 1

  -r resolution
      The resolution of the movie
      Default: the resolution of the first image found 

  -f framerate
      The framerate of the movie, in frames per second. 
      Default: 10 

  -i input_dir
      The directory where are stored the images. 
      The name of the images should be of the form img_xx...x.png where xx...x 
      (n digits) gives the timestamp of the image in ms.
      The timestamps may not start at 0.
      This directory should be writeable.
      Default: the current directory

  -o output_file
      The pathname of the movie. It should end by a suffix that implicitely tells 
      which codec to use, as recognized by ffmpeg (.mp4, .mkv, .avi ...)
      Default: movie.mp4
      
EOF
 exit 1
}


# Defaults
background=""
accel=1
framerate=10
inputdir=$PWD
output=movie.mp4

while getopts hb:r:a:f:i:o: opt ; do
    case $opt in
	h)
	    usage
	    ;;
	b)
	    background="$OPTARG"
	    ;;
	r)
	    resolution="$OPTARG"
	    ;;
	a)
	    accel="$OPTARG"
	    ;;
	i)
	    inputdir="$OPTARG"
	    ;;
	f)
	    framerate="$OPTARG"
	    ;;
	o)
	    output="$OPTARG"
	    ;;
       \?)
           echo "Invalid option: -$OPTARG" >&2
	   exit 1
           ;;
    esac
done

# Check the background image
if [ -z "$background"  -a  -r "$background" ] ; then
    echo "Background image $background not found" >&2
    exit 1
else
    realbackground=$(realpath "$background")
fi

# Check the input directory
if [ -d "$inputdir" ] ; then
    realinputdir=$(realpath "$inputdir")
    cd "$realinputdir"
else
    echo "Directory $inputdir not found" >&2
    exit 1
fi


# Check that there are (at least two) images
#   Array of the image file names
files=( $(ls img_[0-9]*.png) )
nbimg=${#files[@]}

if (( $nbimg < 2 )) ; then
   echo "No images at the right format (img_xx...x.png) found in $realinputdir" >&2
   exit 1
fi

# Check the acceleration value
if (( $accel <=0 )) ; then
    echo "Invalid acceleration (-a option): " $accel
    exit 2
fi

# Take as default the resolution of the first image
if [ -z $resolution ] ; then
  resolution=$(identify -format "%wx%h" ${files[0]})
fi


# ffmpeg concat demuxer descriptor
cdesc=mkmovie_concat.$$.txt

echo cdesc=$cdesc
#echo background=$realbackground
echo background=$background
echo resolution=$resolution
echo accel=$accel
echo framerate=$framerate
echo inputdir=$realinputdir
echo output=$output


# Build the descriptor for the concat demuxer of ffmpeg
# The descriptor contains the list of the filenames of the images
# and the durations (in seconds) between pairs of successive images
current=${files[0]//[![:digit:]]/}
echo file img_${current}.png > $cdesc

LANG=C

for (( i=1; i<=$(expr $nbimg - 1); i++ )) ; do
	next=${files[i]//[![:digit:]]/}
        delta=$(printf "%0.6f\n" $(echo \( $next - $current \) / \( 1000 \* ${accel} \) | bc -ql))      
	echo duration ${delta} >> $cdesc
	current=$next;
	echo file img_${current}.png >> $cdesc
done


# Build the arguments for the background part of the ffmpeg command
if [ "$background" != "" ] ; then
    bg_args="-i $background -filter_complex 'overlay=x=0:y=0'"
#    bg_args="-i $realbackground -filter_complex 'overlay=x=0:y=0'"
    echo bg_args=$bg_args
fi

# Execute the ffmpeg command
echo ffmpeg "$bg_args"  -f concat -safe 0 -i $cdesc -r $framerate -s $resolution $output
eval ffmpeg "$bg_args"  -f concat -safe 0 -i $cdesc -r $framerate -s $resolution $output

# Delete the concat demuxer descriptor
if [ $? = 0 ] ; then
   \rm $cdesc >& /dev/null
fi

