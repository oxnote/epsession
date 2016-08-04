<?php
class Login{
   public function __construct($userid, $passwd){
     $this->userid=$userid;
     $this->passwd=$passwd;
   } 
   
   public function validate(){
     //TODO : 이부분은 각자 완성합니다.
     if ( empty($this->userid) || empty($this->passwd) ){
       return false;
     } else {
       return true;
     }
   }
}
?>