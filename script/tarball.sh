X=verify-policy
#X=certstore

typeset -l version
version=`lsb_release -i -s`
version_id=`lsb_release -r -s`
machine=`uname -m`
issue_date=`date "+%Y%m%d"`

tarball="$X-$2-$version$version_id-$machine-$issue_date".tar.gz

do_mkdir(){
    if [ ! -d "../package" ]; then
        mkdir ../package
    fi
    cd ../package
    rm $X -rf
    mkdir $X
    mkdir $X/bin
}

do_copy(){
    cp ../resource/ $X -rf
    cp ../build/platform/verify-policy $X/bin
    cp ../conf $X -rf
}

do_tarball(){
    tar -zcvf $1 $X
    rm $X -rf
    echo "`date`  BUILD=$X  COMMIT=$2 ARCHIVE=$tarball" >> release.log
}

do_mkdir
do_copy $1
do_tarball $tarball
