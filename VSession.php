<?php
/*
 * Created By Moosun Ahn
 * http://git.vjs.kr
 */
if ( !class_exists( 'VSession' ) ) {
require_once "MYSQL.php";
  
  class VSession {
    public $SID='';
    public $EP='';
    public $TOKEN='';
    public $TOKEN2='';
    public $ERROR='';  //
    //최초 로그인시 id,pwd로 로그인
    //인증되면 md5(ep)를 저장하고 토큰을 발행한다.
 
    public function __construct() {
      $this->ERROR="";
      $this->db = new DB('linkwide', '', 'session');
      $this->EP = $_SERVER['REMOTE_ADDR'].":".$_SERVER['REMOTE_PORT'];
      if (isset($_REQUEST['vtoken'])) $this->TOKEN=$_REQUEST['vtoken'];
      if (isset($_REQUEST['vtoken2'])) $this->TOKEN2=$_REQUEST['vtoken2'];
    }

    //세션을 시작하면 사용자 아이디를 기반으로 기존 세션 데이터를 업데이트하고 새 키를 발급한다.
    //다음부터는 이 키를 이용하여 접속한다.
    public function start($userid, $timeout=20){
      $token=md5($userid.$this->EP);
      $result = $this->db->select('SELECT id From session WHERE userid=?',['userid'=>$userid],['%s']);
      if ($result) {
       $this->db->update('session',['token'=>$token,'ep'=>$this->EP,'timeout'=>$timeout],['%s','%s','%d'],['userid'=>$userid],['%s']);
      } else {
        $this->db->insert('session',['userid'=>$userid,'token'=>$token,'token2'=>md5($userid),'ep'=>$this->EP,'timeout'=>$timeout],['%s','%s','%s','%s','%d']);
      } 
      return '{"vtoken":"'.$token.'"}';
    }
  
   //최초 시도이면 token2를 요청한다.  
   public function check(){
      //find session and end point
      $session = $this->findSession();
      if (empty($session)){
        $this->ERROR="NO_SESSION";
        return false;
      } 

      if ($session[0]->timeout<$session[0]->elapsed){
        $this->ERROR="TIMEOUT";
        return false;        
      }
      if ($session[0]->ep != $_SERVER['REMOTE_ADDR'].":".$_SERVER['REMOTE_PORT'])
      {
        if (!empty($this->TOKEN2)){
          $this->ERROR="INVALID_TOKEN";
          return false;
        } 
        header('vtoken2 required', true, 300);
        return false;
      }
      //오류가 없으면 started_at을 수정한다.
      $this->db->query('UPDATE session SET started_at=now() WHERE token="'.$this->TOKEN.'"');
      return true;
    }
    
    //세션을 끝낸다.
    public function destroy(){
      if (empty($this->TOKEN)) return;
      $this->db->update('session', ['token'=>''],['%s'], ['token'=>$this->TOKEN],['%s']);         
    }
    
    private function findSession(){
      if (empty($this->TOKEN)){
        throw new Exception("Invalid Session Request", 1);
      }
      if (!empty($this->TOKEN2)){
        //TOken and token2가 같으면 EP 업데이트
        $result = $this->db->select('SELECT "'.$this->EP.'" as ep, timeout, TIMESTAMPDIFF(MINUTE,last_accessed_at,now()) as elapsed from session WHERE token=? AND token2=?',[$this->TOKEN,$this->TOKEN2],['%s','%s']);
        if ($result){
          $this->db->update('session', ['ep'=>$this->EP],['%s'], ['token2'=>$this->TOKEN2],['%s']);         
        }
      } else {
          $result = $this->db->select('SELECT ep, timeout, TIMESTAMPDIFF(MINUTE,last_accessed_at,now()) as elapsed from session WHERE token=?',[$this->TOKEN],['%s']);
      }
      return $result;
    }
    
    private function saveSession(){
      $result = $this->db->insert('session',['ep'=>$this->EP,'token'=>$this->TOKEN],['%s','%s']);
      print_r($result);
    }
    
  }
}
?>
