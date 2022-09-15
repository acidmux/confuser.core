﻿#pragma checksum "..\..\Settings.xaml" "{8829d00f-11b8-4213-878b-770e8597ac16}" "65532B09A68980548742C931FF67C0F9BE2FF5220950788D9E82DFE080516B61"
//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

using Confuser;
using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Ink;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;


namespace Confuser {
    
    
    /// <summary>
    /// Settings
    /// </summary>
    public partial class Settings : Confuser.ConfuserTab, System.Windows.Markup.IComponentConnector {
        
        
        #line 22 "..\..\Settings.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox output;
        
        #line default
        #line hidden
        
        
        #line 26 "..\..\Settings.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox sn;
        
        #line default
        #line hidden
        
        
        #line 29 "..\..\Settings.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.CheckBox usePacker;
        
        #line default
        #line hidden
        
        
        #line 32 "..\..\Settings.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.ComboBox packer;
        
        #line default
        #line hidden
        
        
        #line 63 "..\..\Settings.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox seed;
        
        #line default
        #line hidden
        
        private bool _contentLoaded;
        
        /// <summary>
        /// InitializeComponent
        /// </summary>
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "4.0.0.0")]
        public void InitializeComponent() {
            if (_contentLoaded) {
                return;
            }
            _contentLoaded = true;
            System.Uri resourceLocater = new System.Uri("/Confuser;component/settings.xaml", System.UriKind.Relative);
            
            #line 1 "..\..\Settings.xaml"
            System.Windows.Application.LoadComponent(this, resourceLocater);
            
            #line default
            #line hidden
        }
        
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "4.0.0.0")]
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Never)]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Design", "CA1033:InterfaceMethodsShouldBeCallableByChildTypes")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily")]
        void System.Windows.Markup.IComponentConnector.Connect(int connectionId, object target) {
            switch (connectionId)
            {
            case 1:
            this.output = ((System.Windows.Controls.TextBox)(target));
            return;
            case 2:
            
            #line 23 "..\..\Settings.xaml"
            ((System.Windows.Controls.Button)(target)).Click += new System.Windows.RoutedEventHandler(this.OutputSel_Click);
            
            #line default
            #line hidden
            return;
            case 3:
            this.sn = ((System.Windows.Controls.TextBox)(target));
            return;
            case 4:
            
            #line 27 "..\..\Settings.xaml"
            ((System.Windows.Controls.Button)(target)).Click += new System.Windows.RoutedEventHandler(this.SnSel_Click);
            
            #line default
            #line hidden
            return;
            case 5:
            this.usePacker = ((System.Windows.Controls.CheckBox)(target));
            
            #line 31 "..\..\Settings.xaml"
            this.usePacker.Unchecked += new System.Windows.RoutedEventHandler(this.usePacker_Unchecked);
            
            #line default
            #line hidden
            
            #line 31 "..\..\Settings.xaml"
            this.usePacker.Checked += new System.Windows.RoutedEventHandler(this.usePacker_Checked);
            
            #line default
            #line hidden
            return;
            case 6:
            this.packer = ((System.Windows.Controls.ComboBox)(target));
            
            #line 34 "..\..\Settings.xaml"
            this.packer.SelectionChanged += new System.Windows.Controls.SelectionChangedEventHandler(this.packer_SelectionChanged);
            
            #line default
            #line hidden
            return;
            case 7:
            this.seed = ((System.Windows.Controls.TextBox)(target));
            return;
            case 8:
            
            #line 92 "..\..\Settings.xaml"
            ((System.Windows.Controls.Button)(target)).Click += new System.Windows.RoutedEventHandler(this.LoadPlugin_Click);
            
            #line default
            #line hidden
            return;
            }
            this._contentLoaded = true;
        }
    }
}
