   M S B A M L   `   `   `  ???? O  Kmscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e0891&clr-namespace:System;assembly=mscorlibSystem  T PConfuser.Core, Version=1.9.0.0, Culture=neutral, PublicKeyToken=146939e38e0bd61eD2clr-namespace:Confuser.Core;assembly=Confuser.CoreConfuser.Core T:clr-namespace:Confuser.Core.Project;assembly=Confuser.CoreConfuser.Core.Project O KConfuser, Version=1.9.0.0, Culture=neutral, PublicKeyToken=146939e38e0bd61e#clr-namespace:ConfuserConfuser    Confuser.EditRule   R NWindowsBase, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    8x,http://schemas.microsoft.com/winfx/2006/xaml    4sys&clr-namespace:System;assembly=mscorlib    ?cr2clr-namespace:Confuser.Core;assembly=Confuser.Core    Iproj:clr-namespace:Confuser.Core.Project;assembly=Confuser.Core    &localclr-namespace:Confuser      ? Title$  	Edit Rule??$	??300??$	??400?? ? WindowStyle$
 None=? ? AllowsTransparency . 
??????  ? WindowStartupLocation$ CenterOwner=? ? 	Resources  S? 
MethodName S? 
ObjectType   System.Enum   
presetVals S? MethodParameters M? Type  Confuser.Core.Preset  
actionVals-  'Confuser.Core.Project.SettingItemAction	 ?? DataType  Confuser.PrjConfusionCfg
 ?? Padding ? ColumnDefinitions z? SharedSizeGroup ?? Source ?? SelectedValue ?? DisplayMemberPath ?? RelativeSource ?? AncestorType??%?  &	        &	 (     (?? P     *, +)7  S? $ 	GetValues??"   M? "  S? $ 	GetValues??"   M? "  ?? "	  .R??? 
?????? $
 5q?._?? $??25?? ?? $??10 ??? $??70 ??? $??* ?$ cnSize??.+??? $??1??$??2q????? 8    ?? *Action+?? $
 Name??$??2??$??2q????? *Host.Project.Confusions+ ?? *FindAncestor+" ? ?? *Object+.???? -    ??Name$ Chrome?? ?? CornerRadius$ 0??._?? .+??? $??1?????? .???  ? Color$ #FFFFFF?? ? Offset$ 0Q?? $ #000000??$ 1Q?? -    ?Name$
 Root??$??1q????	#40FFFFFF.+?? .+??? $??0q?$??Center=?.??? .+???  J? IsHitTestVisible .  $??10q?$??12(????? *Title+ ?? " ???  .  $??10q?$??12(????? *Title+ ?? " ? J? Effect -  'System.Windows.Media.Effects.BlurEffect     Radius$ 5Q??? -    ??Name$	 Bar??
?????? ?? -   $	??Top=?$??Right=?$??0,5,5,0q?$??20??$??20??|?.  
?????? 
?????? .??F? s????@B ?? ???- ?? ??pr ?.c ? ? ?? р?? ?? ? ?? ?pr р?? @]? ? ? @]? ??pr  ?? ???- @]? ?@B @]? Ѡ.c ?pr 	???	#BBFFFFFF?? $??5,30,5,5q?  BorderBrush#??[ $??1q?  BackgroundBrush#??[ ._?? -   $
 Main?? ? RowDefinitions ?? $??35 ??? $??30 ??? $??* ??? $??35 ? ?? $	??100 ??? $??* ?.+??? $??	Pattern :??$??0??$??0??$??Center=?$??Right=??? -    ??Name$ 
patternBox??$??5q?$??0??$??1??$??Center=?$??Stretch=????? *	Pattern+?? $??Inherit??$??0,0,5,5q?$??Center=?$??Center=?$??1??$??0?? d? 	IsChecked ?? *	Inherit+]? $??1??$??1??$??0,0,5,5q?.+??? $??Preset :??$??Center=?$
??Left=??? $??Right=?$??Center=?$??Stretch=????? # [   ?? *Preset+? $??2??$??2?? ?? $??* ??? $??25 ?.+??? -    ??Name$
 list??$??5,0,5,5q?$??0?????? ?? $??1??.+??? $??20??$??20??$??0,0,5,5q?$??+?????? *
AddCommand+ ?? " ??? $??20??$??20??$??0,0,5,5q?$??-?????? *RemoveCommand+ ?? " ?]? $??3??$??2??.+??? -   $??70??$??5q?$??OK??$
??Left=?$
??Left=? ?? 	IsDefault . ?? -	   $??70??$??5q?$??Cancel??$??Right=?$??Right=?  ?? IsCancel  . 